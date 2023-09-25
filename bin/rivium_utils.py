#!/usr/bin/python
# -*- coding: utf-8 -*-

######################################################
# Rivium Utils Libaries for common Splunk things
# Version 1.1
#
# Changelog
# - 1.0 - Initial development (2020-10-05)
# - 1.1 - Added in conf file and password reading,writing (2020-10-09)
# - 1.2 - Fixed up a missing status check for adding to KV Store (2020-11-12)
######################################################

# Comment Ascii Art
# Ref Large: http://patorjk.com/software/taag/#p=display&f=Standard 
# Ref Small: http://patorjk.com/software/taag/#p=display&f=Calvin%20S

import json, os, sys
import logging
from logging.handlers import TimedRotatingFileHandler

# Requests library needed as KVStore interractions can't use the splunk.rest library due to it URLencoding the postargs
import requests

# Splunk simple REST library ($SPLUNK_HOME/splunk/lib/python3.7/site-packages/splunk/rest)
import splunk
import splunk.rest as rest

# For detailed exeption handling
import linecache
import inspect

##########################################
# Function definitions
# ╔═╗╦ ╦╔╗╔╔═╗╔╦╗╦╔═╗╔╗╔  ╔╦╗╔═╗╔═╗╔═╗
# ╠╣ ║ ║║║║║   ║ ║║ ║║║║   ║║║╣ ╠╣ ╚═╗
# ╚  ╚═╝╝╚╝╚═╝ ╩ ╩╚═╝╝╚╝  ═╩╝╚═╝╚  ╚═╝

# More detailed exception reporting
def detailedException():
	exc_type, exc_obj, tb = sys.exc_info()
	f = tb.tb_frame
	lineno = tb.tb_lineno
	filename = f.f_code.co_filename
	linecache.checkcache(filename)
	line = linecache.getline(filename, lineno, f.f_globals)
	return 'EXCEPTION IN ({}, LINE {} "{}"): Type({}) Object - {}'.format(filename, lineno, line.strip(), exc_type, exc_obj)

# More detailed logging reporting
def fileFunctionLineNumber():
	previous_frame = inspect.currentframe().f_back
	(filename, line_number, function_name, lines, index) = inspect.getframeinfo(previous_frame)
	return "pid=%d,file=%s,func=%s,line=%d" % (os.getpid(),os.path.basename(filename),function_name,line_number)

##############################################
# Setup Logging
# ╔═╗╔═╗╔╦╗╦ ╦╔═╗  ╦  ╔═╗╔═╗╔═╗╦╔╗╔╔═╗
# ╚═╗║╣  ║ ║ ║╠═╝  ║  ║ ║║ ╦║ ╦║║║║║ ╦
# ╚═╝╚═╝ ╩ ╚═╝╩    ╩═╝╚═╝╚═╝╚═╝╩╝╚╝╚═╝

def loggingSetup(splunkAppName, logfileDescriptor, logLevel = logging.INFO):
	# Log Testing
	# tail -f /opt/splunk/var/log/splunk/TA-addressify_app_setuphandler.log

	#set up logging to this location
	SPLUNK_HOME = os.environ.get("SPLUNK_HOME")
	LOG_FILENAME = os.path.join(SPLUNK_HOME,"var/log/splunk/" + splunkAppName + "_" + logfileDescriptor + ".log")

	# Set up a specific logger
	logger = logging.getLogger(splunkAppName)

	#default logging level , can be overidden in stanza config
	logger.setLevel(logLevel)

	#log format
	formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')

	# Add the daily rolling log message handler to the logger
	handler = TimedRotatingFileHandler(LOG_FILENAME, when="d",interval=1,backupCount=5)
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	return logger

##############################################
# Load up config from apps conf file
# ╦  ╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔╗╔╔═╗╦╔═╗
# ║  ║ ║╠═╣ ║║  ║  ║ ║║║║╠╣ ║║ ╦
# ╩═╝╚═╝╩ ╩═╩╝  ╚═╝╚═╝╝╚╝╚  ╩╚═╝

def configLoad(splunkAppName, confFilename, splunkSessionKey, stanza = None):

	logger = logging.getLogger(splunkAppName)

	try:
		# If no stanza provided use confFilename with _config appended to the end.
		if stanza is None:
			stanza = '%s_config' % confFilename

		# Load up previous config
		# curl -k -u admin:pass https://localhost:8089/servicesNS/nobody/TA-addressify/configs/conf-addressify/addressify_config
		uri = '/servicesNS/nobody/%s/configs/conf-%s/%s' % (splunkAppName, confFilename, stanza)
		response, content = rest.simpleRequest(uri, sessionKey=splunkSessionKey, getargs={'output_mode': 'json'})

		restContents = json.loads(content)
		logger.debug("%s,response.status=%s,restContents=%s" % (fileFunctionLineNumber(),response["status"], restContents["entry"][0]["content"]))

		return restContents["entry"][0]["content"]

	except Exception:
		logger.error("%s,App has not been configured yet %s" % (fileFunctionLineNumber(),detailedException()))

##############################################
# Write to config from apps conf file
# ╦ ╦╦═╗╦╔╦╗╔═╗  ╔═╗╔═╗╔╗╔╔═╗╦╔═╗
# ║║║╠╦╝║ ║ ║╣   ║  ║ ║║║║╠╣ ║║ ╦
# ╚╩╝╩╚═╩ ╩ ╚═╝  ╚═╝╚═╝╝╚╝╚  ╩╚═╝
#
# contents - Must be a dictionary

def configWrite(splunkAppName, confFilename, contents, splunkSessionKey, stanza = None):

	logger = logging.getLogger(splunkAppName)

	try:
		# If no stanza provided use confFilename with _config appended to the end.
		if stanza is None:
			stanza = '%s_config' % confFilename

		# Create a conf file with the stanza myweblogs 
		# curl -k -u admin:pass https://localhost:8089/servicesNS/nobody/TA-addressify/configs/conf-addressify -d name=addressify_config -d SHOULD_LINEMERGE=false -d CHARSET=UTF-8 
		uri = '/servicesNS/nobody/%s/configs/conf-%s/%s' % (splunkAppName, confFilename,stanza)
		response, content = rest.simpleRequest(uri, 
			sessionKey=splunkSessionKey, 
			postargs=contents, 
			method='POST', 
			getargs={'output_mode': 'json'})

		restContents = json.loads(content)
		logger.debug("%s,message=Config stanza create,response.status=%s,restContents=%s" % (fileFunctionLineNumber(),response["status"], restContents["entry"][0]["content"]))

	except Exception as e:
		logger.error("%s,message=Failed to write to local/%s.conf: %s" % (fileFunctionLineNumber(), confFilename, detailedException()))
	else:
		logger.info("%s,message=,Successfully wrote to local/%s.conf" % (fileFunctionLineNumber(),confFilename))

##############################################
# Reload config from apps conf file. Used after updating a conf file to remind Splunk to refresh the contents in memory : TODO: Doesn't seem to work.
# ╦═╗╔═╗╦  ╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔╗╔╔═╗
# ╠╦╝║╣ ║  ║ ║╠═╣ ║║  ║  ║ ║║║║╠╣ 
# ╩╚═╚═╝╩═╝╚═╝╩ ╩═╩╝  ╚═╝╚═╝╝╚╝╚  
#

def configReload(splunkAppName, confFilename, splunkSessionKey):

	logger = logging.getLogger(splunkAppName)

	try:
		# If no stanza provided use confFilename with _config appended to the end.

		# Create a conf file with the stanza myweblogs 
		# curl -k -u admin:pass https://localhost:8089/servicesNS/nobody/TA-addressify/configs/conf-addressify/_reload -d name=addressify_config -d SHOULD_LINEMERGE=false -d CHARSET=UTF-8 
		uri = '/servicesNS/nobody/%s/configs/conf-%s/_reload' % (splunkAppName, confFilename)
		logger.debug("%s,message=Calling reload endpoint %s" % (fileFunctionLineNumber(),uri))
		response, content = rest.simpleRequest(uri, 
			sessionKey=splunkSessionKey, 
			method='GET', 
			getargs={'output_mode': 'json'})

		restContents = json.loads(content)
		logger.debug("%s,message=Config stanza create,response.status=%s,restContents=%s" % (fileFunctionLineNumber(),response["status"], restContents))

	except Exception as e:
		logger.error("%s,message=Failed to reload local/%s.conf: %s" % (fileFunctionLineNumber(), confFilename, detailedException()))
	else:
		logger.info("%s,message=,Successfully reloaded local/%s.conf" % (fileFunctionLineNumber(),confFilename))

##############################################
# Reload config from an entire app
# ╦═╗╔═╗╦  ╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔╗╔╔═╗
# ╠╦╝║╣ ║  ║ ║╠═╣ ║║  ║  ║ ║║║║╠╣ 
# ╩╚═╚═╝╩═╝╚═╝╩ ╩═╩╝  ╚═╝╚═╝╝╚╝╚  
#

def configReloadApp(splunkAppName, splunkSessionKey):

	logger = logging.getLogger(splunkAppName)

	try:
		# If no stanza provided use confFilename with _config appended to the end.

		# Create a conf file with the stanza myweblogs 
		# curl -k -u admin:pass https://localhost:8089/servicess/apps/local/TA-addressify/ -d name=addressify_config -d SHOULD_LINEMERGE=false -d CHARSET=UTF-8 
		uri = '/services/apps/local/%s/' % (splunkAppName)
		logger.debug("%s,message=Calling reload endpoint %s" % (fileFunctionLineNumber(),uri))
		response, content = rest.simpleRequest(uri, 
			sessionKey=splunkSessionKey, 
			method='GET', 
			getargs={'refresh': 'true'})

		restContents = json.loads(content)
		logger.debug("%s,message=Config stanza create,response.status=%s,restContents=%s" % (fileFunctionLineNumber(),response["status"], restContents))

	except Exception as e:
		logger.error("%s,message=Failed to reload app configurations: %s" % (fileFunctionLineNumber(), detailedException()))
	else:
		logger.info("%s,message=,Successfully reloaded configurations" % (fileFunctionLineNumber()))



##############################################
# Load up password from password store
# ╦  ╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔═╗╔═╗╦ ╦╔═╗╦═╗╔╦╗
# ║  ║ ║╠═╣ ║║  ╠═╝╠═╣╚═╗╚═╗║║║║ ║╠╦╝ ║║
# ╩═╝╚═╝╩ ╩═╩╝  ╩  ╩ ╩╚═╝╚═╝╚╩╝╚═╝╩╚══╩╝

def loadPassword(splunkAppName, confFilename, splunkSessionKey, usernameToAssociatePasswordTo = "addressify_api_key"):

	logger = logging.getLogger(splunkAppName)
	response = None
	
	try:
		confPassword = None

		# Load up previous passwords from store
		uri = '/servicesNS/nobody/%s/storage/passwords/%s:%s:' % (splunkAppName,splunkAppName,usernameToAssociatePasswordTo)
		response, content = rest.simpleRequest(uri, sessionKey=splunkSessionKey, getargs={'output_mode': 'json'})

		restContents = json.loads(content)
#		logger.debug("%s,response.status=%s,restContents=%s" % (fileFunctionLineNumber(),response["status"], restContents["entry"][0]["content"]))

		confUsername = restContents["entry"][0]["content"]["username"]
		confPassword = restContents["entry"][0]["content"]["clear_password"]

		restContents = json.loads(content)

		# Redact password for logging
		redacted4Logging = restContents["entry"][0]["content"].copy()
		redacted4Logging["clear_password"] = "***** redacted for logging *****"
		logger.debug("%s,section=loadPassword,response.status=%s,content=%s,message=REST API call for password store parameters response" % (fileFunctionLineNumber(),response["status"], json.dumps(redacted4Logging)))

		if response["status"] == "200":
			logger.info("%s,username=%s,realm=%s,response.status=%s,message=Successfully loaded password from password store" % (fileFunctionLineNumber(),usernameToAssociatePasswordTo, splunkAppName, response["status"]))
			return confPassword, response["status"]
		else:
			logger.error("%s,username=%s,realm=%s,response.status=%s,message=Failed to load password from password store" % (fileFunctionLineNumber(),usernameToAssociatePasswordTo, splunkAppName, response["status"]))
			return "", response["status"]

	except splunk.ResourceNotFound as e:
		logger.error("%s,username=%s,realm=%s,response.status=404,message=Password did not exist in password store." % (fileFunctionLineNumber(),usernameToAssociatePasswordTo, splunkAppName))
		return "", 404
	except Exception:
		logger.error("%s,username=%s,realm=%s,response.status=unknown,message=Failed to load password from password store %s" % (fileFunctionLineNumber(),usernameToAssociatePasswordTo, splunkAppName, detailedException()))
		return "", 404

# Delete old entry from password store
# ╔╦╗╔═╗╦  ╔═╗╔╦╗╔═╗  ╔═╗╔═╗╔═╗╔═╗╦ ╦╔═╗╦═╗╔╦╗
#  ║║║╣ ║  ║╣  ║ ║╣   ╠═╝╠═╣╚═╗╚═╗║║║║ ║╠╦╝ ║║
# ═╩╝╚═╝╩═╝╚═╝ ╩ ╚═╝  ╩  ╩ ╩╚═╝╚═╝╚╩╝╚═╝╩╚══╩╝
def deletePassword(splunkAppName, splunkSessionKey, usernameToAssociatePasswordTo):

	logger = logging.getLogger(splunkAppName)

	try:
		# delete old API key from password store
		# curl -k -u admin:pass -X DELETE https://localhost:8089/servicesNS/nobody/TA-addressify/storage/passwords/addressify:addressify_api_key:
		uri = '/servicesNS/nobody/%s/storage/passwords/%s:%s:' % (splunkAppName,splunkAppName,usernameToAssociatePasswordTo)
		response, content = rest.simpleRequest(uri, 
			sessionKey=splunkSessionKey, 
			method='DELETE', 
			getargs={'output_mode': 'json'})
		
		logger.debug("%s,message=passwordDelete,response.status=%s" % (fileFunctionLineNumber(),response["status"]))

	except splunk.ResourceNotFound:
		logger.info("%s,message=Previous password never set." % (fileFunctionLineNumber()))
	except Exception as e:
		logger.error("%s,message=Failed to clear password store: %s" % (fileFunctionLineNumber(),detailedException()))
	else:
		logger.info("%s,message=Successfully cleared password store" % (fileFunctionLineNumber()))

# Create/Update entry in password store
# ╔═╗╦═╗╔═╗╔═╗╔╦╗╔═╗  ╔═╗╦═╗  ╦ ╦╔═╗╔╦╗╔═╗╔╦╗╔═╗  ╔═╗╔═╗╔═╗╔═╗╦ ╦╔═╗╦═╗╔╦╗
# ║  ╠╦╝║╣ ╠═╣ ║ ║╣   ║ ║╠╦╝  ║ ║╠═╝ ║║╠═╣ ║ ║╣   ╠═╝╠═╣╚═╗╚═╗║║║║ ║╠╦╝ ║║
# ╚═╝╩╚═╚═╝╩ ╩ ╩ ╚═╝  ╚═╝╩╚═  ╚═╝╩  ═╩╝╩ ╩ ╩ ╚═╝  ╩  ╩ ╩╚═╝╚═╝╚╩╝╚═╝╩╚══╩╝
def createUpdatePassword(splunkAppName, splunkSessionKey, usernameToAssociatePasswordTo, passwordToEncrypt):

	logger = logging.getLogger(splunkAppName)

	try:
		
		# create API key in password store
		# curl -k -u admin:pass https://localhost:8089/servicesNS/nobody/TA-addressify/storage/passwords -d name=thisusername -d password=thispassword -d realm=ip-hub
		uri = '/servicesNS/nobody/%s/storage/passwords' % splunkAppName
		response, content = rest.simpleRequest(uri, 
			sessionKey=splunkSessionKey, 
			postargs={'name': usernameToAssociatePasswordTo, 'password': passwordToEncrypt, 'realm': splunkAppName}, 
			method='POST', 
			getargs={'output_mode': 'json'})

		restContents = json.loads(content)

		# redacting password for logger
		restContents["entry"][0]["content"]["clear_password"] = "****** REDACTED FOR LOGGING ******"
		logger.debug("%s,message=Successfully created password store entry,response.status=%s,restContents=%s" % (fileFunctionLineNumber(),response["status"], restContents["entry"][0]["content"]))

	except Exception as e:
		logger.error("%s,message=Failed to write to password store: %s" % (fileFunctionLineNumber(), detailedException()))
	else:
		logger.info("%s,response.status=%s,message=Successfully wrote to password store" % (fileFunctionLineNumber(),response["status"]))

##############################################
# Load KVStore
# ╦  ╔═╗╔═╗╔╦╗  ╦╔═╦  ╦╔═╗╔╦╗╔═╗╦═╗╔═╗
# ║  ║ ║╠═╣ ║║  ╠╩╗╚╗╔╝╚═╗ ║ ║ ║╠╦╝║╣ 
# ╩═╝╚═╝╩ ╩═╩╝  ╩ ╩ ╚╝ ╚═╝ ╩ ╚═╝╩╚═╚═╝
#
# Ref: https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/kvstore/usetherestapitomanagekv/

def loadKVStore(splunkAppName, splunkSessionKey, KVStore):

	try:
		logger = logging.getLogger(splunkAppName)

		# curl -k -u admin:yourpassword https://localhost:8089/servicesNS/nobody/kvstoretest/storage/collections/data/kvstorecoll

	except Exception:
		logger.error("%s,message=Failed to load KV Store : %s" % (fileFunctionLineNumber(),detailedException()))
	else:
		logger.info("%s,Successfully loaded KV Store results" % fileFunctionLineNumber())



##############################################
# Query KVStore
# ╔═╗ ╦ ╦╔═╗╦═╗╦ ╦  ╦╔═╦  ╦╔═╗╔╦╗╔═╗╦═╗╔═╗
# ║═╬╗║ ║║╣ ╠╦╝╚╦╝  ╠╩╗╚╗╔╝╚═╗ ║ ║ ║╠╦╝║╣ 
# ╚═╝╚╚═╝╚═╝╩╚═ ╩   ╩ ╩ ╚╝ ╚═╝ ╩ ╚═╝╩╚═╚═╝
#
# Ref: https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/kvstore/usetherestapitomanagekv/

def queryKVStore(splunkAppName, splunkSessionKey, KVStore, query):

	try:
		logger = logging.getLogger(splunkAppName)

		logger.debug("%s,message=Calling KVStore" % (fileFunctionLineNumber()))
		limit = 1

		# curl -k -u admin:yourpassword https://localhost:8089/servicesNS/nobody/kvstoretest/storage/collections/data/kvstorecoll?query=%7B%22id%22%3A%7B%22%24gt%22%3A24%7D%7D
		# curl -k -u admin:yourpassword https://localhost:8089/servicesNS/nobody/TA-addressify/storage/collections/data/addressify_cache?query=%7B%22id%22%3A%20%2213.226.106.197%22%7D
		# query is URLEncoded - https://www.urlencoder.org/
		# query = {"id": {"$gt": 24}}

		KVStoreURI = "/servicesNS/nobody/%s/storage/collections/data/%s" % (splunkAppName,KVStore)
		data = {"limit":limit, "query":json.dumps(query)}
		response, content = rest.simpleRequest(KVStoreURI, sessionKey=splunkSessionKey, getargs=data)

		if response.status == 200:				
			logger.debug("%s,response.status=%d,message=Found KVStore results" % (fileFunctionLineNumber(),response.status))
			return content
		else:
			logger.error("%s,response.status=%d,message=KVStore error returned : %s" % (fileFunctionLineNumber(),response.status,response))
			return None

	except Exception:
		logger.error("%s,message=Failed to query KV Store : %s" % (fileFunctionLineNumber(),detailedException()))

##############################################
# Get KVStore Entry
# ╔═╗╔═╗╔╦╗  ╦╔═╦  ╦╔═╗╔╦╗╔═╗╦═╗╔═╗  ╔═╗╔╗╔╔╦╗╦═╗╦ ╦
# ║ ╦║╣  ║   ╠╩╗╚╗╔╝╚═╗ ║ ║ ║╠╦╝║╣   ║╣ ║║║ ║ ╠╦╝╚╦╝
# ╚═╝╚═╝ ╩   ╩ ╩ ╚╝ ╚═╝ ╩ ╚═╝╩╚═╚═╝  ╚═╝╝╚╝ ╩ ╩╚═ ╩ 
#
# Ref: https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/kvstore/usetherestapitomanagekv/

def getKVStoreEntry(splunkAppName, splunkSessionKey, KVStore, _key):

	try:
		logger = logging.getLogger(splunkAppName)

		logger.debug("%s,message=Calling KVStore" % (fileFunctionLineNumber()))
		limit = 1

		# curl -k -u admin:yourpassword https://localhost:8089/servicesNS/nobody/kvstoretest/storage/collections/data/kvstorecoll?query=%7B%22id%22%3A%7B%22%24gt%22%3A24%7D%7D
		# curl -k -u admin:yourpassword https://localhost:8089/servicesNS/nobody/TA-addressify/storage/collections/data/addressify_cache?query=%7B%22id%22%3A%20%2213.226.106.197%22%7D
		# query is URLEncoded - https://www.urlencoder.org/
		# query = {"id": {"$gt": 24}}

		KVStoreURI = "/servicesNS/nobody/%s/storage/collections/data/%s" % (splunkAppName,KVStore)
		data = {"limit":limit, "query":json.dumps(query)}
		response, content = rest.simpleRequest(KVStoreURI, sessionKey=splunkSessionKey, getargs=data)

		if response.status == 200:				
			logger.debug("%s,response.status=%d,message=Found KVStore results" % (fileFunctionLineNumber(),response.status))
			return content
		else:
			logger.error("%s,response.status=%d,message=KVStore error returned : %s" % (fileFunctionLineNumber(),response.status,response))
			return None

	except Exception:
		logger.error("%s,message=Failed to get record from KV Store : %s" % (fileFunctionLineNumber(),detailedException()))


##############################################
# Clear KVStore Entires Completely (WARNING WARNING)
# ╔═╗╦  ╔═╗╔═╗╦═╗  ╦╔═╦  ╦╔═╗╔╦╗╔═╗╦═╗╔═╗
# ║  ║  ║╣ ╠═╣╠╦╝  ╠╩╗╚╗╔╝╚═╗ ║ ║ ║╠╦╝║╣ 
# ╚═╝╩═╝╚═╝╩ ╩╩╚═  ╩ ╩ ╚╝ ╚═╝ ╩ ╚═╝╩╚═╚═╝
#
# Ref: https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/kvstore/usetherestapitomanagekv/

def clearKVStore(splunkAppName, splunkSessionKey, KVStore):

	try:
		logger = logging.getLogger(splunkAppName)

		# curl -k -u admin:yourpassword -X DELETE https://localhost:8089/servicesNS/nobody/TA-addressify/storage/collections/data/addressify_cache

		KVStoreURI = "/servicesNS/nobody/%s/storage/collections/data/%s" % (splunkAppName,KVStore)
		response, content = rest.simpleRequest(KVStoreURI, sessionKey=splunkSessionKey, getargs={'output_mode': 'json'},  method='DELETE')

		if response.status == 200:				
			logger.debug("%s,response.status=%d,message=Cleared contents of KVStore : %s" % (fileFunctionLineNumber(),response.status,response))
		else:
			logger.error("%s,response.status=%d,message=Error clearing KVStore : %s" % (fileFunctionLineNumber(),response.status,response))

	except Exception:
		logger.error("%s,message=Failed to clear KV Store : %s" % (fileFunctionLineNumber(),detailedException()))

##############################################
# Delete Entry from KVStore
# ╔╦╗╔═╗╦  ╔═╗╔╦╗╔═╗  ╦╔═╦  ╦╔═╗╔╦╗╔═╗╦═╗╔═╗  ╔═╗╔╗╔╔╦╗╦═╗╦ ╦
#  ║║║╣ ║  ║╣  ║ ║╣   ╠╩╗╚╗╔╝╚═╗ ║ ║ ║╠╦╝║╣   ║╣ ║║║ ║ ╠╦╝╚╦╝
# ═╩╝╚═╝╩═╝╚═╝ ╩ ╚═╝  ╩ ╩ ╚╝ ╚═╝ ╩ ╚═╝╩╚═╚═╝  ╚═╝╝╚╝ ╩ ╩╚═ ╩ 
#
# Ref: https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/kvstore/usetherestapitomanagekv/

def deleteKVStoreEntry(splunkAppName, splunkSessionKey, KVStore, _key):

	try:
		logger = logging.getLogger(splunkAppName)

		# curl -k -u admin:yourpassword -X DELETE https://localhost:8089/servicesNS/nobody/TA-addressify/storage/collections/data/addressify_cache/the_key

		KVStoreURI = "/servicesNS/nobody/%s/storage/collections/data/%s/%s" % (splunkAppName,KVStore,_key)
		response, content = rest.simpleRequest(KVStoreURI, sessionKey=splunkSessionKey, getargs={'output_mode': 'json'},  method='DELETE')

		if response.status == 200:				
			logger.debug("%s,response.status=%d,_key=%s,message=Deleted KV Store Entry : %s" % (fileFunctionLineNumber(),response.status,_key,response))
		else:
			logger.error("%s,response.status=%d,_key=%s,message=Error Deleting KV Store Entry : %s" % (fileFunctionLineNumber(),response.status,_key,response))

	except Exception:
		logger.error("%s,message=Failed to clear KV Store : %s" % (fileFunctionLineNumber(),detailedException()))


##############################################
# Write to KVStore
# ╦ ╦╦═╗╦╔╦╗╔═╗  ╔╦╗╔═╗  ╦╔═╦  ╦╔═╗╔╦╗╔═╗╦═╗╔═╗
# ║║║╠╦╝║ ║ ║╣    ║ ║ ║  ╠╩╗╚╗╔╝╚═╗ ║ ║ ║╠╦╝║╣ 
# ╚╩╝╩╚═╩ ╩ ╚═╝   ╩ ╚═╝  ╩ ╩ ╚╝ ╚═╝ ╩ ╚═╝╩╚═╚═╝
#
# Ref: https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/kvstore/usetherestapitomanagekv/

def writeToKVStore(splunkAppName, splunkSessionKey, KVStore, values, keyFields = None, _key = None):

	try: 
		logger = logging.getLogger(splunkAppName)

		# The splunk.rest library urlencodes the postargs so is incompatible with the KVStore REST API requirements.
		# So we gotta break with tradition and use requests library instead with doesn't include all the jibber jabber

		# Common Settings used by all write types
		splunkBaseURL = "https://localhost:8089"
		KVStoreURI = "/servicesNS/nobody/%s/storage/collections/data/%s" % (splunkAppName,KVStore)
		KVStoreURI = "%s/%s" % (splunkBaseURL, KVStoreURI)
		headers = {'Content-Type': 'application/json', 'Authorization': 'Splunk ' + splunkSessionKey}
		data = json.dumps(values) 

		# if Splunk KVStore _key provided update it directly
		if not _key is None:
			logger.debug("%s,message=Updating _key directly : %s" % (fileFunctionLineNumber(),_key))

			# Update Existing Record
			# curl -k -u admin:yourpassword \
			# https://localhost:8089/servicesNS/nobody/kvstoretest/storage/collections/data/kvstorecoll/5410be5441ba15298e4624d1 \
			# -H 'Content-Type: application/json' \
			# -d '{"name": "new_name"}'

			# Append the _key to the URI
			KVStoreURI = "%s/%s" % (KVStoreURI,_key)

		# Perform Query based on Key fields provided
		elif(not keyFields is None):
			logger.debug("%s,message=Checking if entry already exists : %s" % (fileFunctionLineNumber(),keyFields))

			# Query for record matching keyFields
			query = {}
			for key in keyFields:
				if key in values:
					query[key] = values[key]

			logger.debug("%s,query=%s,message=Querying KV Store" % (fileFunctionLineNumber(),query))
			foundInKVStore = False
			resp = queryKVStore(splunkAppName, splunkSessionKey, KVStore, query)
			response = json.loads(resp.decode("utf-8"))
			if response is not None:
				if(isinstance(response,list)):
					if len(response) > 0:
						logger.debug("%s,message=Found record in KVStore" % (fileFunctionLineNumber()))
						foundInKVStore = True
						_key = response[0]['_key']
						
			# Update existing Record
			if foundInKVStore:
				logger.debug("%s,message=Updating Existing Record" % (fileFunctionLineNumber()))

				# Update Existing Record
				# curl -k -u admin:yourpassword \
				# https://localhost:8089/servicesNS/nobody/kvstoretest/storage/collections/data/kvstorecoll/5410be5441ba15298e4624d1 \
				# -H 'Content-Type: application/json' \
				# -d '{"name": "new_name"}'

				# Append the _key to the URI
				KVStoreURI = "%s/%s" % (KVStoreURI,_key)

		# Finally perform write to KVStore
		logger.debug("%s,message=Writing data to KVStore,headers=%s,payload=%s" % (fileFunctionLineNumber(),headers,data))
		r = requests.post(KVStoreURI, data, verify=False, headers=headers)

		if r.status_code == 200:
			logger.debug("%s,response.status=%d,message=Added to KVStore : %s" % (fileFunctionLineNumber(),r.status_code,r.text))
		elif r.status_code == 201:
			logger.debug("%s,response.status=%d,message=Added to KVStore : %s" % (fileFunctionLineNumber(),r.status_code,r.text))
		else:
			logger.error("%s,response.status=%d,message=Failed adding to KVStore : %s" % (fileFunctionLineNumber(),r.status_code,r.text))



	except Exception:
		logger.error("%s,message=Failed to write to KV Store : %s" % (fileFunctionLineNumber(),detailedException()))

