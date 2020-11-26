#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
from botocore.exceptions import ClientError

import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 'codebuild_enum_projects',
    'services': ['CodeBuild'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Enumerates CodeBuild builds and projects while looking for sensitive data',
    'name': 'ADD_NAME_HERE' ,
}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')

def main(args, awsattack_main, data=None):

    args = parser.parse_args(args)

    import_path = 'ttp.src.codebuild_enum_builds_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = ''
    for region in sorted(data):
        out += '    {}\n'.format(region)
        for val in data[region]:
            out += '        {} {} found.\n'.format(data[region][val], val[:-1] + '(' + val[-1] + ')')
    return out
