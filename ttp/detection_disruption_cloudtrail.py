#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 'detection_disruption_alarms',
    'services': ['CloudTrail'],
    'prerequisite_modules': ['detection_enum_services_cloudtrail'],
    'arguments_to_autocomplete': ['--action', '--trails'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Disables, deletes, or minimizes various logging/monitoring services.',
    'name': 'ADD_NAME_HERE' ,

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--action', required=True, default=None, help='If you want to disable (dis) or delete (del)')
parser.add_argument('--trails', required=False, default=None, help='Comma-separated list of CloudTrails trail names and regions to target instead of enumarating them. They should be formatted like trail_name@region.')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.detection_disruption_cloudtrail_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0) 
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=technique_info)

def summary(data, awsattack_main):
    out = ''
    if 'cloudtrail' in data:
        out += '  CloudTrail:\n'
        out += '    {} trail(s) disabled.\n'.format(data['cloudtrail']['disabled'])
        out += '    {} trail(s) deleted.\n'.format(data['cloudtrail']['deleted'])
        out += '    {} trail(s) minimized.\n'.format(data['cloudtrail']['minimized'])
    
    return out
