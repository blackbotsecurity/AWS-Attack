#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 'detection_disruption_guardduty',
    'services': ['GuardDuty'],
    'prerequisite_modules': ['detection_enum_services_guardduty'],
    'arguments_to_autocomplete': ['--action', '--detectors'],
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
parser.add_argument('--detectors', required=False, default=None, help='Comma-separated list of GuardDuty detector IDs and regions to target, instead of enumerating them. They should be formatted like detector_id@region.')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.detection_disruption_guardduty_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0) 
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=technique_info)

def summary(data, awsattack_main):
    out = ''
    if 'guardduty' in data:
        out += '  GuardDuty:\n'
        out += '    {} detector(s) disabled.\n'.format(data['guardduty']['disabled'])
        out += '    {} detector(s) deleted.\n'.format(data['guardduty']['deleted'])
    if 'cloudtrail' in data:
        out += '  CloudTrail:\n'
        out += '    {} trail(s) disabled.\n'.format(data['cloudtrail']['disabled'])
        out += '    {} trail(s) deleted.\n'.format(data['cloudtrail']['deleted'])
        out += '    {} trail(s) minimized.\n'.format(data['cloudtrail']['minimized'])
    if 'awsconfig' in data:
        out += '  AWSConfig:\n'
        out += '    Rules:\n'
        out += '      {} rule(s) deleted.\n'.format(data['awsconfig']['rules']['deleted'])
        out += '    Recorders:\n'
        out += '      {} recorder(s) deleted.\n'.format(data['awsconfig']['recorders']['deleted'])
        out += '      {} recorder(s) stopped.\n'.format(data['awsconfig']['recorders']['stopped'])
        out += '    Aggregators:\n'
        out += '      {} aggregator(s) deleted.\n'.format(data['awsconfig']['aggregators']['deleted'])
    if 'vpc' in data:
        out += '  VPC:\n'
        out += '    {} flow log(s) deleted.\n'.format(data['vpc']['deleted'])
    
    
    return out
