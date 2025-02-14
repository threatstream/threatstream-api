# threatstream-api.py
#
# Copyright (C) 2014 THREAT STREAM, Inc.
# This file is subject to the terms and conditions of the GNU General Public
# License version 2.  See the file COPYING in the main directory for more
# details.
import requests
import logging as log
from sys import exit, argv
 
__version__ = 2
__author__ = 'ThreatStream LABS - NMA'

apiuser = 'TS_Username' # Or Specify on the commandline
apikey = 'TS_APIKey' # Or Specify on the commandline
query_api_url = 'https://api.threatstream.com/api/v2'

log.basicConfig(format='%(message)s', level=log.INFO)


def query_api(apiuser,apikey,resource,flags):
    url = '{}/{}/?username={}&api_key={}{}'.format(query_api_url, resource, apiuser, apikey, flags)
    try:
      http_req = requests.get(url, headers={'ACCEPT': 'application/json, text/html'})
      if http_req.status_code == 200: return(http_req.json()['objects']) # Return JSON Blob
      elif http_req.status_code == 401: 
        log.error('Access Denied. Check API Credentials')
        exit(0)
      else: log.info('API Connection Failure. Status code: {}'.format(http_req.status_code))
    except Exception as err:
      log.error('API Access Error: {}'.format(err))
      exit(0)
       

def fetch_intel(apiuser,apikey, *args):
  if args: query = args[0]
  else: query = ''
  r = []
  log.info('Downloading intelligence: \n')
  INTEL = { 'c2_domain', 'bot_ip' } # filter to itype
  limit = 3 # Limit number of responses
  status = "active" 
  for itype in INTEL:
    r.append(query_api(apiuser,apikey,'intelligence',
      '&extend_source=true&value__re=.*{}.*&limit={}&status={}&itype={}'.format(query, limit, status, itype)))
  return(r)

def format_output(jsonblob):
  r = ""
  for line in jsonblob:
      for k, v in line.items():
        if not v: continue
        r += "{}: {}\n".format(k, v)
  return(r)


if __name__ == '__main__':
  if len(argv) < 2:
    log.info('Usage: {} [query] [username] [apikey]'.format(__file__))
    exit(0)
  if len(argv) == 4:
    apiuser = argv[2]
    apikey = argv[3]
  response = (fetch_intel(apiuser, apikey, argv[1]))
  for line in response:
    print(format_output(line)) ## Make human readable. 

