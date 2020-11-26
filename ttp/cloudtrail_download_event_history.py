#!/usr/bin/env python3
import datetime
import argparse
import json
import time
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1530',
    'external_id': '',
    'controller': 'cloudtrail_download_event_history',
    'services': ['CloudTrail'],
    'prerequisite_modules': [],
    'external_dependecies': [],
    'arguments_to_autocomplete': ['--regions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Downloads CloudTrail event history to JSON files.',
    'name': 'ADD_NAME_HERE' ,

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')

def main(args, awsattack_main):
    args = parser.parse_args(args)
    import_path = 'ttp.src.cloudtrail_download_event_history_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)
    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = ''
    for region in data:
        out += '  {} Event(s) found for {}.\n'.format(data[region], region)
    return out
