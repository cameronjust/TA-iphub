
# ###################################
# TA-iphub Splunk addon


## About
This addon provides a custom search command for interracting with IpHub APIs.

> IPHub is an IP lookup website featuring Proxy/VPN detection. A free API is available, so you can perform fraud checks on online stores, detect malicious players on online games and much more!

Ref: https://iphub.info/

* Author: Cameron Just
* Version: 1.1.6
* Splunkbase URL: n/a
* Source type(s): n/a
* Has index-time operations: No
* Input requirements: None
* Supported product(s): Search Heads

## Usage
On installation you will need to go to the apps setup page and enter your iphub.info API key. They offer a free APIs key for up to 1000 requests/day.

Once setup just run any search which contains IP addresses and feed them into the custom search command.

Usage:

>  \<search  command  with  ip  address\> | iphub field=[field_name_with_ip_address]

Example: 

> | makeresults count=10 | eval dest_ip = if((random()%3) == 1, "8.8.8.8", "4.4.4.4") | iphub field=dest_ip

## Clearing KVStore

/opt/splunk/bin/splunk clean  kvstore -app TA-iphub -collection iphub_cache

## Developer Tips

Setup pages use a ridiculous number of files so make sure you edit them all when making changes. This is the most painful part of the whole app creation. Good luck!!!
 * bin/iphub_setup_handler.py - Writes conf files to local/iphub.conf and stores the API key in the password store
 * default/restmap.conf - Defines the Splunk REST endpoints related to configurations
 * default/data/ui/views/setup_page.xml - Renders the form for entering setup config in the web GUI
 * appserver/static/setup_page.css - Make config page pretty
 * appserver/static/setup_page.js - Javascript which pulls the existing app config from Splunk via a call to Splunk REST endpoints
 * default/web.conf - Allows the setup endpoints to be visible externally so the javascript on the configuration page can poll the API for previously configred settings

The search commands that actually does all the useful things use less files
 * default/commands.conf - Tells Splunk about the search command
 * bin/iphub.py - Runs the search command


Troubleshooting errors with setup page not saving correctly
index=_internal source=*TA-iphub_setuphandler.log

If things arenot working with setup pages make sure you have a default/iphub.conf as there are issues with unconfigured apps.

Try to get to the endpoint for the config files
https://192.168.64.60:8089/servicesNS/nobody/TA-iphub/configs/conf-iphub/iphub_config?output_mode=json


## Changelog

* 1.0.0 - Initial development (2020-10-09)
* 1.1.0 - Added the ability to skip API poll for internal IP addresses & extended KVStore fields to allow for direct lookups with native Splunk queries (2020-10-28)
* 1.1.1 - Fixed bug with internal IP address dummyPrivateIpResponse (2020-11-09)
* 1.1.2 - Added detection of setup complete (2022-05-31)
* 1.1.3 - Added proxy configuration options (2022-05-31)
* 1.1.4 - Updated Splunklib and fixed some python upgrade readiness issues (2022-06-07) - https://github.com/splunk/splunk-sdk-python
* 1.1.5 - Added additonal exception checking and raising to Splunk GUI for issues (2022-06-08)
* 1.1.6 - Fixed a bug with the proxy server configs (2023-09-26)

## ToDo

- [ ] Include option for modifying the cache expiry date
- [x] Ensure functionality exists for no KVStore Usage
- [ ] Improvements to Error Reporting

  
  

## Splunk App Inspect Results
