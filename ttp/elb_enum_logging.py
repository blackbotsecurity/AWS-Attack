#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
import time
import importlib
from botocore.exceptions import ClientError

target = ''

technique_info = {
    'blackbot_id': 'T1082',
    'external_id': '',
    'controller': 'elb_enum_logging',
    'services': ['ElasticLoadBalancing'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--regions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Collects a list of Elastic Load Balancers without access logging.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.elb_enum_logging_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)


def summary(data, awsattack_main):
    out = '  {} Load balancer(s) have been found\n'.format(data['load_balancers'])
    if data['logless'] > 0:
        out += '  {} Load balancer(s) found without logging\n'.format(data['logless'])
        out += '  List of Load balancers without logging saved to:\n    {}\n'.format(data['csv_file_path'])
    return out
