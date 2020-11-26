import json
import os
import logging
import copy
import traceback
# Lee 5/13/2020: Added evidence encoding + JSON logging
from base64 import b64encode
from time import time
from datetime import datetime
import json
import requests


# Lee - upload each event to elasticsearch (in addition to writing the event to disk)
# this function accepts a python dict as input, converts it to json and uploads it to elasticsearch (hard-coded localhost:9200 for now)

#BUG:  serialization issue caused by parsing error when parsing datetime: we run ec2__enum

def do_api_upload(event_log):
    encoded_event = {
            'data': b64encode(json.dumps(event_log, default=str).encode()).decode(),
            'c2':   'awsattack',
        }
    encoded_event  = json.dumps(encoded_event)
    timestamp      = datetime.utcfromtimestamp(int(time())).strftime('%Y-%m-%dT%H:%M:%SZ')
    enrichment_api = 'http://127.0.0.1:8099/api/v1/ingest'
    headers        = {'content-type': 'application/json'}
    logfile        = '/var/log/ue1ac201.elasticsearch.log'

    try:
        api_response = requests.post(enrichment_api, timeout=8, headers=headers, data=encoded_event)
        fd = open(logfile, 'a')
        fd.write(f'[{timestamp}] API Response from upload: {api_response.text}\n[{timestamp}] Event from upload attempt: {event_log}\n')
        fd.close()
    except Exception as err:
        fd = open(logfile, 'a')
        fd.write(f'[{timestamp}] Failed to upload event: {encoded_event}\n')
        fd.close()


def elasticsearch_upload(event_log):
    timestamp = datetime.utcfromtimestamp(int(time())).strftime('%Y-%m-%dT%H:%H:%SZ')
    try:
        elasticsearch = 'http://127.0.0.1:9200/awsattack/_doc'
        headers = {'content-type': 'application/json'}
        api_response = requests.post(elasticsearch, timeout=5, headers=headers, data=json.dumps(event_log))
        logfile = '/var/log/ue1ac201.elasticsearch.log'
        fd = open(logfile, 'a')
        fd.write(f'[{timestamp}] API Response from upload: {api_response.text}\n[{timestamp}] Event from upload attempt: {event_log}\n')
        fd.close()
    except Exception as err:
        logfile = '/var/log/ue1ac201.elasticsearch_error.log'  # record errors here - wont see errors unless elasticsearch is not running
        #TODO: monitor failed event logs
        fd = open(logfile, 'a')
        fd.write(f'[{timestamp}] Failed to upload event: {event_log}\n')
        fd.close()

