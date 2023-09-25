#!/usr/bin/python
# -*- coding: utf-8 -*-

# Comment Ascii Art
# Ref Large: http://patorjk.com/software/taag/#p=display&f=Standard 
# Ref Small: http://patorjk.com/software/taag/#p=display&f=Calvin%20S

import os,logging, json, pprint
import sys

import rivium_utils as utils

import splunk
import splunk.admin
import splunk.entity as entity

# For Splunk rest API calls
import splunk.rest as rest

from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from logging.handlers import TimedRotatingFileHandler

# For detailed exeption handling
import linecache
import inspect

##############################################
# Addon Setup Page Configuration
#     _    ____  ____   ___  _   _   ____  _____ _____ _   _ ____    ____   _    ____ _____ ____  
#    / \  |  _ \|  _ \ / _ \| \ | | / ___|| ____|_   _| | | |  _ \  |  _ \ / \  / ___| ____/ ___| 
#   / _ \ | | | | | | | | | |  \| | \___ \|  _|   | | | | | | |_) | | |_) / _ \| |  _|  _| \___ \ 
#  / ___ \| |_| | |_| | |_| | |\  |  ___) | |___  | | | |_| |  __/  |  __/ ___ \ |_| | |___ ___) |
# /_/   \_\____/|____/ \___/|_| \_| |____/|_____| |_|  \___/|_|     |_| /_/   \_\____|_____|____/ 


class ConfigHandler(splunk.admin.MConfigHandler):

    # Some constants to make porting this app for other purposes easier
    splunkAppName = "TA-iphub"
    scriptName = os.path.basename(__file__)
    confFilename = "iphub"
    logLevel = logging.DEBUG
    logfileDescriptor = "setuphandler"
    # logLevel = logging.INFO
    SPLUNK_HOME = os.environ.get("SPLUNK_HOME")
    appLogger = None

    # Default method required
    def setup(self):
        try:

            self.appLogger = utils.loggingSetup(self.splunkAppName,self.logfileDescriptor)
            self.appLogger.setLevel(self.logLevel)

            self.appLogger.info("%s,message=Setup Starting." % (utils.fileFunctionLineNumber()))
            
            # Define the supported variables for the setup pages
            if self.requestedAction == splunk.admin.ACTION_EDIT:
                for arg in ['credential_key' ]:
                    self.supportedArgs.addOptArg(arg)           
                for arg in ['credential' ]:
                    self.supportedArgs.addOptArg(arg)
                for arg in ['useKVStore' ]:
                    self.supportedArgs.addOptArg(arg)
                for arg in ['debugLogging' ]:
                    self.supportedArgs.addOptArg(arg)
                for arg in ['proxy_settings' ]:
                    self.supportedArgs.addOptArg(arg)
                
        except:  
            self.appLogger.error("%s,message=Error during setup method. : %s" % (utils.fileFunctionLineNumber(),utils.detailedException()))

        self.appLogger.info("%s,message=Setup Completed." % (utils.fileFunctionLineNumber()))

    # Default method required when listing the contents of previous configurations
    def handleList(self, confInfo):

        try:
            self.appLogger = utils.loggingSetup(self.splunkAppName,self.logfileDescriptor)
            self.appLogger.setLevel(self.logLevel)

            self.appLogger.info("%s,message=handleList starting." % (utils.fileFunctionLineNumber()))
            username_to_associate_password_to = "iphub_api_key"
        
            # Load up previous passwords from store
            storedPassword, responseStatus = utils.loadPassword(self.splunkAppName, self.confFilename, self.getSessionKey(), "iphub_api_key")
            confInfo['iphub'].append('credential_key', "iphub_api_key")
            confInfo['iphub'].append('credential', storedPassword)

            # Load up previous config
            configContents = utils.configLoad(self.splunkAppName, self.confFilename, self.getSessionKey())
            confInfo['iphub'].append('useKVStore', configContents["useKVStore"])
            confInfo['iphub'].append('debugLogging', configContents["debugLogging"])
            confInfo['iphub'].append('proxy_settings', configContents["proxy_settings"])

            # retrieve the generic settings from conf file

            self.appLogger.info("%s,message=handleList ending." % (utils.fileFunctionLineNumber()))

        except Exception as e:
            self.appLogger.error("%s,message=Error during handleList method. : %s" % (utils.fileFunctionLineNumber(),utils.detailedException()))



    # Default method required for updating configuration changes
    def handleEdit(self, confInfo):

        try:
            self.appLogger = utils.loggingSetup(self.splunkAppName,self.logfileDescriptor)
            self.appLogger.setLevel(self.logLevel)

            self.appLogger.info("%s,message=handleEdit starting." % (utils.fileFunctionLineNumber()))

            # Commented out as it will contain the password used to encrypt and you don't want that in the logs    on a regular basis
#            self.appLogger.debug("%s,message=arguments passed to handleEdit %s." % (utils.fileFunctionLineNumber(),self.callerArgs.data))

            if self.callerArgs.data['credential_key'][0] in [None, '']:
                self.callerArgs.data['credential_key'][0] = ''
            
            if self.callerArgs.data['credential'][0] in [None, '']:
                self.callerArgs.data['credential'][0] = ''
            
            if self.callerArgs.data['useKVStore'][0] in [None, '']:
                self.callerArgs.data['useKVStore'][0] = ''
            
            if self.callerArgs.data['debugLogging'][0] in [None, '']:
                self.callerArgs.data['debugLogging'][0] = ''

            if self.callerArgs.data['proxy_settings'][0] in [None, '']:
                self.callerArgs.data['proxy_settings'][0] = ''
            
            credential_key = self.callerArgs.data['credential_key'][0]                 
            credential = self.callerArgs.data['credential'][0]
            useKVStore = self.callerArgs.data['useKVStore'][0]
            debugLogging = self.callerArgs.data['debugLogging'][0]
            proxy_settings = self.callerArgs.data['proxy_settings'][0]

            username_to_associate_password_to = "iphub_api_key"
            password_to_encrypt = credential

            # https://community.splunk.com/t5/Developing-for-Splunk-Enterprise/Manipulate-conf-file-through-Splunk-Rest-API/td-p/91568
            # https://docs.splunk.com/Documentation/Splunk/8.0.6/RESTTUT/RESTconfigurations

            # Clear old entry from password store
            utils.deletePassword(self.splunkAppName, self.getSessionKey(), username_to_associate_password_to)

            # Add entry to password store
            utils.createUpdatePassword(self.splunkAppName, self.getSessionKey(), username_to_associate_password_to, password_to_encrypt)

            # Save other config information into <splunkAppName>.conf
            contents = {'useKVStore': useKVStore, 'debugLogging': debugLogging, 'proxy_settings': proxy_settings}
            utils.configWrite(self.splunkAppName, self.confFilename, contents, self.getSessionKey())

            # Reload .conf so Splunk knows what you just setup. TODO Doesn't seem to work so reloading entire app at the end of this function
#            utils.configReload(self.splunkAppName, self.confFilename, self.getSessionKey())

            # Write to app.conf to set app as configured
            contents = {'is_configured': 1}
            utils.configWrite(self.splunkAppName, "app", contents, self.getSessionKey(), "install")

            # Reload app.conf so Splunk knows you've just configured the setup page. Stops it asking you to setup the app.  TODO Doesn't seem to work so reloading entire app at in the next line
#            utils.configReload(self.splunkAppName, "app", self.getSessionKey())

            # Reload the entire apps config. Stops it asking you to setup the app.
            utils.configReloadApp(self.splunkAppName, self.getSessionKey())

            self.appLogger.info("%s,message=handleEdit ending." % (utils.fileFunctionLineNumber()))

        except:  
            self.appLogger.error("%s,message=Error during handleEdit : %s." % (utils.fileFunctionLineNumber(), utils.detailedException()))


def main():
    splunk.admin.init(ConfigHandler, splunk.admin.CONTEXT_NONE)


if __name__ == '__main__':

    main()
