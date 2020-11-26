#!/usr/bin/env python3
import datetime

import argparse
import requests
import zipfile
import os
import re
import importlib

from core.secretfinder.utils import regex_checker, contains_secret, Color
from botocore.exceptions import ClientError

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 'lambda_enum',
    'services': ['Lambda'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions', '--versions-all'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020',
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Enumerates data from AWS Lambda.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')
parser.add_argument('--versions-all', required=False, default=False, action='store_true', help='Grab all versions instead of just the latest')

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.lambda_enum_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = ''
    for region in sorted(data):
        out += '  {} functions found in {}. View more information in the DB \n'.format(data[region], region)
    if not out:
        out = '  Nothing was enumerated'

    out += 'Functions: {}'.format(data['Functions'])
    return out

