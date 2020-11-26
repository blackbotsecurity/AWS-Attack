#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1518.b.002',
    'external_id': '',
    'controller': 'waf_enum',
    'services': ['waf', 'waf-regional'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--regions', '--global-region'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. ' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Detects rules and rule groups for WAF.',
    'name': 'Cloud Service Discovery: Security Service Discovery',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument(
    '--regions',
    required=False,
    default=None,
    help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all available regions.'
)
parser.add_argument(
    '--global-region',
    required=False,
    default=False,
    action='store_true',
    help='Flag to enumerate WAF information for all regions.'
)


def main(args, awsattack_main):
    args = parser.parse_args(args)
     
    import_path = 'ttp.src.waf_enum_src' 
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = ''
    for key in data:
        out += '  Found {} Total {}.\n'.format(data[key], key)
    return out
