#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 'detection_disruption_vpc',
    'services': ['Config'],
    'prerequisite_modules': ['detection_enum_services_vpc'],
    'arguments_to_autocomplete': ['--action', '--flow-logs'],
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

parser.add_argument('--alarms', required=False, default=None, help='Comma-separated list of CloudWatch alarm names and regions to target, instead of enumerating them. They should be formatted like alarm_name@region.')
parser.add_argument('--action', required=True, default=None, help='If you want to delete the flow logs(y) or not (n). (y,n)')

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.detection_disruption_vpc_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0) 
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=technique_info)

def summary(data, awsattack_main):
    out = ''
    if 'vpc' in data:
        out += '  VPC:\n'
        out += '    {} flow log(s) deleted'.format(data['vpc']['deleted'])
    
    return out
