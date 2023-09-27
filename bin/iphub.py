#!/usr/bin/python
# -*- coding: utf-8 -*-

# Comment Ascii Art
# Ref Large: http://patorjk.com/software/taag/#p=display&f=Standard 
# Ref Small: http://patorjk.com/software/taag/#p=display&f=Calvin%20S

# Test for parsing errors with
# /opt/splunk/bin/splunk cmd python /opt/splunk/etc/apps/TA-iphub/bin/iphub.py searchargs

# Logs
# tail -f /opt/splunk/var/log/splunk/TA-iphub_api.log

# Test Search
# | tstats  count FROM datamodel=Edgerouter.EdgerouterFirewall WHERE (nodename=EdgerouterFirewall.TrafficOUT.OUT_SYN "EdgerouterFirewall.SRC"="192.168.64.90") BY _time span=auto "EdgerouterFirewall.DST" | rename "EdgerouterFirewall.DST" as DST | dedup DST | iphub field="DST"

import sys, os, json, logging, inspect, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, os.pardir)))
import requests

# used for detecting internal IP addresses
import functools
import ipaddress

import rivium_utils as utils

####
# Splunk VS Code Debugging - https://github.com/splunk/vscode-extension-splunk/wiki/Debugging
sys.path.append(os.path.join(os.environ['SPLUNK_HOME'],'etc','apps','SA-VSCode','bin'))
# import splunk_debug as dbg
#dbg.enable_debugging(timeout=25)
####


# Load up Splunklib (App inspect recommends splunklib goes into the appname/lib directory)
libPathName = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),'..','lib'))
sys.path.append(libPathName)
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from splunklib.six.moves import range

# Splunk simple REST library ($SPLUNK_HOME/splunk/lib/python3.7/site-packages/splunk/rest)
import splunk.rest as rest

# Normal Splunk REST call
# def simpleRequest(path, sessionKey=None, getargs=None, postargs=None, method='GET', raiseAllErrors=False, proxyMode=False, rawResult=False, timeout=None, jsonargs=None, token=False):


##########################################
# Search Command Definition
# ╔═╗╔═╗╔═╗╦═╗╔═╗╦ ╦  ╔═╗╔═╗╔╦╗╔╦╗╔═╗╔╗╔╔╦╗  ╔╦╗╔═╗╔═╗╦╔╗╔╦╔╦╗╦╔═╗╔╗╔
# ╚═╗║╣ ╠═╣╠╦╝║  ╠═╣  ║  ║ ║║║║║║║╠═╣║║║ ║║   ║║║╣ ╠╣ ║║║║║ ║ ║║ ║║║║
# ╚═╝╚═╝╩ ╩╩╚═╚═╝╩ ╩  ╚═╝╚═╝╩ ╩╩ ╩╩ ╩╝╚╝═╩╝  ═╩╝╚═╝╚  ╩╝╚╝╩ ╩ ╩╚═╝╝╚╝

# https://github.com/splunk/splunk-sdk-python/blob/7645d29b7fc1166c554bf9a7a03f40a02529ccc4/splunklib/searchcommands/search_command.py#L97
# https://github.com/splunk/splunk-sdk-python/blob/7645d29b7fc1166c554bf9a7a03f40a02529ccc4/splunklib/searchcommands/streaming_command.py#L26

@Configuration(distributed=False)
class iphubCommand(StreamingCommand):
    """
     | iphub [field="ip"]]
     """

    # parameters specific to this addon
    field  = Option(name='field',  require=True)
    API_key = "MTxxxxxxxxxxxxxxxxxxxxxxxxxRTM="
    useKVStore = False
    debugLogging = False
    ignoreInternalIPs = True
    KVStore = "iphub_cache"
    daysToCache = 30
    dummyPrivateIpResponse = {"ip": "", "countryCode": "ZZ", "countryName": "ZZ", "asn": 0, "isp": "Private or unnanounced IP", "block": 0}
    suppress_error = False
    proxies = {}

    # Some constants to make porting this app for other purposes easier
    splunkAppName = "TA-iphub"
    scriptName = os.path.basename(__file__)
    confFilename = "iphub"
    confStanza = "api_config"
    logLevel = logging.DEBUG
    logfileDescriptor = "api"
    appLogger = None
    # logLevel = logging.INFO

    # Simple translation of block codes from IPHub to something more human friendly
    def blockTranslate(self, blockCode):
        if (blockCode == 0):
            return "residential"
        elif (blockCode == 1):
            return "non-residential"
        elif (blockCode == 2):
            return "both"
        else:
            return "unknown"


    # Retrieve configuration parameters
    # ╦  ╔═╗╔═╗╔╦╗  ╔═╗╔═╗╔╗╔╔═╗╦╔═╗╔═╗
    # ║  ║ ║╠═╣ ║║  ║  ║ ║║║║╠╣ ║║ ╦╚═╗
    # ╩═╝╚═╝╩ ╩═╩╝  ╚═╝╚═╝╝╚╝╚  ╩╚═╝╚═╝
    def loadConfigs(self):

        self.appLogger.debug("Loading configuration parameters")

        try:
            splunkSessionKey = self.metadata.searchinfo.session_key
            confSettings = utils.configLoad(self.splunkAppName,self.confFilename,splunkSessionKey)

            if "useKVStore" in confSettings: 
                if confSettings["useKVStore"] == "1":
                    self.useKVStore = True
                else:
                    self.useKVStore = False

                self.appLogger.info("%s,message=KVStore setting of %d found in local/%s.conf." % (utils.fileFunctionLineNumber(), self.useKVStore, self.confFilename))

            else:
                self.appLogger.warning("%s,message=No KV Store config found in local/%s.conf." % (utils.fileFunctionLineNumber(), self.confFilename))

            # Check if KVStore exists
            try:
                # Check KV Store Exists
                # curl -k -u admin:pass https://localhost:8089//servicesNS/nobody/TA-iphub/storage/collections/config/iphub_cache 

                KVStoreURI = "/servicesNS/nobody/%s/storage/collections/data/%s" % (self.splunkAppName,self.KVStore)
                response, content = rest.simpleRequest(KVStoreURI, sessionKey=splunkSessionKey, getargs={'output_mode': 'json'})
                if response.status == 200:                
                    self.appLogger.debug("%s,section=KVStoreCheck,response.status=%d,message=Found KVStore" % (utils.fileFunctionLineNumber(),response.status))
                else:
                    self.appLogger.debug("%s,section=KVStoreCheck,response.status=%d,message=KV Store not found : %s" % (utils.fileFunctionLineNumber(),response.status,response))

            except Exception:
                self.appLogger.error("%s,section=KVStoreCheck,message=Exception %s." % (utils.fileFunctionLineNumber(),utils.detailedException()))
                raise Exception("KV Store couldn't be found check error logs")

            if "debugLogging" in confSettings: 
                if confSettings["debugLogging"] == "1":
                    self.debugLogging = True
                    self.appLogger.setLevel(logging.DEBUG)
                else:
                    self.debugLogging = False
                    self.appLogger.setLevel(logging.INFO)

                self.appLogger.info("%s,message=debugLogging setting of %d found in local/%s.conf." % (utils.fileFunctionLineNumber(), self.debugLogging, self.confFilename))

            else:
                self.appLogger.warning("%s,message=No debug config found in local/%s.conf." % (utils.fileFunctionLineNumber(),self.confFilename))

            # Loading the iphub.info API key
            self.API_key, responseStatus = utils.loadPassword(self.splunkAppName, self.confFilename, splunkSessionKey, "iphub_api_key")

            # Loading the proxy server config
            try:
                if "proxy_settings" in confSettings:
                    proxy_server = confSettings["proxy_settings"]

                    # Check if blank
                    if proxy_server.strip() != "":
                    
                        # append in http:// if it's missing
                        if not proxy_server.startswith("http"):
                            proxy_server = 'http://' + proxy_server
                        
                        try:
                            self.proxies = {'http': proxy_server, 'https': proxy_server}
                            response = requests.get("https://example.com/", proxies=self.proxies)
                            if response.status_code == 200:
                                self.appLogger.debug("%s,section=ProxyCheck,message=Proxy Test connection successful" % (utils.fileFunctionLineNumber()))
                            else:
                                self.appLogger.error("%s,section=ProxyCheck,message=Proxy server test connection to %s failed. Not setting a proxy server." % (utils.fileFunctionLineNumber(),proxy_server))
                                self.proxies = {}
                        
                        except requests.exceptions.ProxyError as proxy_err:
                            self.appLogger.error("%s,section=ProxyCheck,message=Proxy error %s." % (utils.fileFunctionLineNumber(), proxy_err))

                            if '407' in str(proxy_err):
                                raise Exception("Proxy test failed due to authorisation required for proxy server. Not yet supported by addon. Only workaround is to include username and password in the proxy URL like this http://proxy_user:proxy_password@my.proxy.server.com:8443")
                            else:
                                raise Exception("Proxy test failed due to authorisation required for proxy server. Proxy error was %s" % proxy_err)

                        except Exception as e:
                            self.appLogger.error("%s,section=ProxyCheck,message=Proxy server test connection to %s failed. Will skip use of proxy. Exception %s." % (utils.fileFunctionLineNumber(),proxy_server, utils.detailedException()))
                            raise e
            except Exception as e:
                self.appLogger.error("%s,section=ProxyCheck,message=Exception %s." % (utils.fileFunctionLineNumber(),utils.detailedException()))
                raise e
                            
        except Exception as e:
            self.appLogger.error("%s,message=Exception %s." % (utils.fileFunctionLineNumber(),utils.detailedException()))
            raise e
                    
    # Streaming Processor
    # ╔═╗╔╦╗╦═╗╔═╗╔═╗╔╦╗╦╔╗╔╔═╗  ╔═╗╦═╗╔═╗╔═╗╔═╗╔═╗╔═╗╔═╗╦═╗
    # ╚═╗ ║ ╠╦╝║╣ ╠═╣║║║║║║║║ ╦  ╠═╝╠╦╝║ ║║  ║╣ ╚═╗╚═╗║ ║╠╦╝
    # ╚═╝ ╩ ╩╚═╚═╝╩ ╩╩ ╩╩╝╚╝╚═╝  ╩  ╩╚═╚═╝╚═╝╚═╝╚═╝╚═╝╚═╝╩╚═
    def stream(self, events):
        #dbg.set_breakpoint()

        try:

            # Setup logger
            self.appLogger = utils.loggingSetup(self.splunkAppName,self.logfileDescriptor)
            self.appLogger.setLevel(logging.DEBUG)

            self.loadConfigs()
            self.appLogger.info('%s,iphubCommand=%s', (utils.fileFunctionLineNumber(),self))

            #logger.info("Config Settings %s" % self._configuration)
            #logger.info("Headers %s" % self._input_header)
            
            # Use sessions as requested by iphub.info for HTTPS requests
            self.appLogger.info("%s,message=streaming started setting up session with iphub." % utils.fileFunctionLineNumber())
            session = requests.Session()
            session.proxies = self.proxies
            
            splunkSessionKey = self.metadata.searchinfo.session_key

            # Counters
            eventsProcessed = 0
            ipHubCalls = 0
            cachedEntries = 0
            skippedInternalIPs = 0
            isPrivateIP = False
            errors = 0

            for event in events:
                
                if not self.field in event :
                    continue

                try:
                    ip = event[self.field]
                    basicSanityCheck = False
                    
                    # Check if it's a valid IP
                    try:

                        # This will throw an error if this string is not an IP
                        isPrivateIP = ipaddress.IPv4Address(ip).is_private
                        basicSanityCheck = True

                    except Exception as e:
                        self.appLogger.error("%s,section=ipSanityCheck,message=%s" % (utils.fileFunctionLineNumber(),utils.detailedException()))
                        basicSanityCheck = False
                        event["iphub_error"] = "not an IPV4 address"
                        eventsProcessed = eventsProcessed + 1
                        errors = errors + 1
                        yield event
                        continue

                    # Should we ignore sending internal IP address requests to iphub
                    if self.ignoreInternalIPs and isPrivateIP:

                        self.appLogger.debug("%s,section=internalIP,internal_ip=1,ip=%s,message=Internal IP Address detected" % (utils.fileFunctionLineNumber(), ip))
                        self.dummyPrivateIpResponse["ip"] = ip

                        for key in self.dummyPrivateIpResponse:

                            # Skip hostname field as we already have that and IPHub asks not to use this field
                            if key=="hostname": continue

                            # Add all remaining fields
                            self.appLogger.debug("%s,section=reponseFieldParsing,%s=%s" % (utils.fileFunctionLineNumber(), key, self.dummyPrivateIpResponse[key]))
                            event["iphub_" + key] = self.dummyPrivateIpResponse[key]

                            if (key == "block"):
                                event["iphub_block_desc"] = self.blockTranslate(self.dummyPrivateIpResponse[key])

                        # set cache value to 2 as a signal it was skipped due to internal IP address checks
                        event["iphub_cached"] = 2

                        # Return enriched event back to Splunk
                        eventsProcessed = eventsProcessed + 1
                        skippedInternalIPs = skippedInternalIPs + 1
                        yield event
                        continue

                    if basicSanityCheck:
                        self.appLogger.debug("%s,section=ipSanityCheck,passed=1,ip=%s" % (utils.fileFunctionLineNumber(), ip))

                        # Check KV Store for entry
                        self.appLogger.debug("%s,section=checkKvStore,ip=%s" % (utils.fileFunctionLineNumber(), ip))
                        hasKVStoreEntry = False
                        query = {"ip": ip}
                        resp = utils.queryKVStore(self.splunkAppName, splunkSessionKey, self.KVStore, query)
                        response = json.loads(resp.decode("utf-8"))
                        self.appLogger.debug("%s,section=KVStoreResponse,response=%s" % (utils.fileFunctionLineNumber(), response))

                        # Multiple sanity checks on the data
                        if response is not None:
                            if(isinstance(response,list)):
                                if len(response) > 0:
                                    if 'date_modified' in response[0] and '_key' in response[0]:
                                        # Check if date_modified is still within valid cache time limit
                                        if int(response[0]['date_modified']) > time.time() - (self.daysToCache*24*60*60):
                                            self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry still valid using it instead of looking up iphub for new one,date_modified=%s,_key=%s" % (utils.fileFunctionLineNumber(), response[0]['date_modified'], response[0]['_key']))
                                            hasKVStoreEntry = True

                                        # It's OLD purge from KV Store
                                        else:
                                            self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry expired we are going to delete it get a new one" % (utils.fileFunctionLineNumber()))
                                            utils.deleteKVStoreEntry(self.splunkAppName, splunkSessionKey, self.KVStore, response[0]['_key'])
                                    else:
                                        self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry reponse didn't have date_modified or _key field,response=%s" % (utils.fileFunctionLineNumber(),response[0]))
                                else:
                                    self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry reponse was zero length" % (utils.fileFunctionLineNumber()))
                            else:
                                self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry reponse wasn't a list" % (utils.fileFunctionLineNumber()))
                        else:
                            self.appLogger.debug("%s,section=KVStoreResponse,message=KVStoreEntry reponse didn't exist" % (utils.fileFunctionLineNumber()))


                            
                        if(hasKVStoreEntry):

                            # Increment Counter
                            cachedEntries = cachedEntries + 1

                            entry = response[0]['response']

                            # Marker field to tell if this result was cached from KVStore or not
                            event["iphub_cached"] = 1
                            for key in entry:
                                
                                # Skip hostname, _user, _key or date_modified fields
                                if key=="hostname" or key=="_user" or key=="_key" or key=="date_modified": continue

                                # Add all remaining fields
                                self.appLogger.debug("%s,section=KVStoreReponseFieldParsing,%s=%s" % (utils.fileFunctionLineNumber(), key, entry[key]))
                                event["iphub_" + key] = entry[key]

                                if (key == "block"):
                                    event["iphub_block_desc"] = self.blockTranslate(entry[key])

                        # Poll IPHub for result
                        else:
                            try:
                                # Increment Counter
                                ipHubCalls = ipHubCalls + 1

                                # Marker field to tell if this result was cached from KVStore or not
                                event["iphub_cached"] = 0

                                # Poll API if a valid IP address
                                # curl http://v2.api.iphub.info/ip/118.209.251.2 -H "X-Key: MTxxxxxxxxxxxxxxxxxxxxxxxxxRTMTM="
                                headers = {'X-Key': self.API_key}

                                url = 'https://v2.api.iphub.info/ip/%s' % (ip)
                                self.appLogger.debug("%s,section=iphubCall,requestUrl=%s" % (utils.fileFunctionLineNumber(), url))
    
                                try:
                                    result = session.get(url, headers=headers, verify=False)
                                    result_json = json.loads(result.text)

                                    self.appLogger.debug("%s,section=reponseParsing,status=%d,message=Call returned" % (utils.fileFunctionLineNumber(), result.status_code))
                                
                                    # Check the result status code
                                    if result.status_code == 200:
                                        # Request was successful, handle the result data
                                        self.appLogger.debug("%s,section=reponseParsing,payload=%s" % (utils.fileFunctionLineNumber(), result_json))
                                        
                                        print(result.text)
                                    elif result.status_code == 401 or result.status_code == 403 :
                                        # Handle a 401 Unauthorised error
                                        self.appLogger.error("%s,section=reponseParsing,401 unauthorised error. Check your API key" % (utils.fileFunctionLineNumber()))
                                        raise Exception("%d unauthorised/forbidden error returned from IPHub. Check API Key in setup page." % result.status_code)
                                    elif result.status_code >= 400:
                                        self.appLogger.error("%s,section=reponseParsing,%d response error with payload %s" % (utils.fileFunctionLineNumber(), result.status_code, result_json))
                                        raise Exception("%d error returned from IPHub. Check _internal Splunk logs." % result.status_code)

                                except requests.exceptions.RequestException as e:
                                    # Handle network or other request-related errors
                                    self.appLogger.error("%s,section=reponseParsing,Unexpected Network Request Error from API call %s" % (utils.fileFunctionLineNumber(), utils.detailedException()))
                                    raise e

                                except Exception as e:
                                    self.appLogger.error("%s,section=reponseParsing,Unexpected Error during API call %s" % (utils.fileFunctionLineNumber(), utils.detailedException()))
                                    raise e
    
                                for key in result_json:

                                    # Skip hostname field as we already have that
                                    if key=="hostname": continue

                                    # Add all remaining fields
                                    self.appLogger.debug("%s,section=reponseFieldParsing,%s=%s" % (utils.fileFunctionLineNumber(), key, result_json[key]))
                                    event["iphub_" + key] = result_json[key]

                                    if (key == "block"):
                                        event["iphub_block_desc"] = self.blockTranslate(result_json[key])

                                # Insert/Update iphub results to KV Store
                                record = {}
                                record["date_modified"] = int(time.time())
                                record["ip"] = result_json["ip"]
                                record["country_code"] = result_json["countryCode"]
                                record["isp"] = result_json["isp"]
                                record["block_desc"] = event["iphub_block_desc"]
                                record["response"] = result_json

                                utils.writeToKVStore(self.splunkAppName, splunkSessionKey, self.KVStore, record, keyFields = ["ip"])

                            except Exception as e:
                                self.appLogger.error("%s,section=iphubpolling,message=%s" % (utils.fileFunctionLineNumber(),utils.detailedException()))
                                if not self.suppress_error:
                                    raise e


                    else:
                        self.appLogger.warning("%s,section=ipSanityCheck,passed=0,ip=%s" % (utils.fileFunctionLineNumber(), ip))


                except Exception as e:
                    self.appLogger.error("%s,section=iphubpolling,message=%s" % (utils.fileFunctionLineNumber(),utils.detailedException()))
                    if not self.suppress_error:
                        raise e

                # Return enriched event back to Splunk
                eventsProcessed = eventsProcessed + 1
                yield event

            self.appLogger.info("%s,eventCount=%d,ipHubCalls=%d,cachedEntries=%d,skippedInternalIPs=%d,message=streaming ended" % (utils.fileFunctionLineNumber(),eventsProcessed,ipHubCalls,cachedEntries,skippedInternalIPs))

        except Exception as e:
            self.appLogger.error("%s,section=outerTry,message=%s" % (utils.fileFunctionLineNumber(),utils.detailedException()))
            raise e
#            self.appLogger.error(utils.detailedException())

# logger.debug("section=argumentsPassed,%s" % (sys.argv))

# for line in sys.stdin:
#    logger.debug("section=stdIn,%s" % (line))
    
dispatch(iphubCommand, sys.argv, sys.stdin, sys.stdout, __name__)

