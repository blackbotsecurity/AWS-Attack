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
    'controller': 'lambda_check_functions',
    'services': ['Lambda'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--get-evidence-from'],
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
parser.add_argument('--get-evidence-from', required=True, help='lambda_enum')

def main(args, awsattack_main):
    args = parser.parse_args(args)

    if args.get_evidence_from != 'lambda_enum':
        awsattack_main.print('USAGE ERROR: Invalid ttp. \n')
        return None

    command = f'run {args.get_evidence_from}'.split(' ')
    data = awsattack_main.exec_technique(command, chain=True)

    import_path = 'ttp.src.lambda_check_functions_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=data)

def summary(data, awsattack_main):
    out = ''
    for region in sorted(data):
        out += '  {} functions found in {}. View more information in the DB \n'.format(data[region], region)
    if not out:
        out = '  Nothing was enumerated'
    return out

