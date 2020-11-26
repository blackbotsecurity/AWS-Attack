#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
from random import choice

import importlib
import os
import string

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 'ecs_enum_services',
    'services': ['ECS'],
    'prerequisite_modules': ['ecs_enum_clusters'],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--get-evidence-from', '--regions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'This module enumerates information from ECS',
    'name': 'ADD_NAME_HERE',
}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

# Short term to chain techniques. Future: api calls and rust.
parser.add_argument('--get-evidence-from', required=True, help='ecs_enum_clusters')
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')

def main(args, awsattack_main, data=None):
    args = parser.parse_args(args)
    current_directory = os.getcwd()
    
    if args.get_evidence_from != 'ecs_enum_clusters':
        awsattack_main.print('USAGE ERROR: Invalid ttp')
        return None

    command = f'run {args.get_evidence_from}'.split(' ')
    data = awsattack_main.exec_technique(command, chain=True)

    import_path = 'ttp.src.ecs_enum_services_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)
       
    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=data)

def summary(data, awsattack_main):
    results = []

    results.append('    Regions:')
    for region in data['regions']:
        results.append('   {}'.format(region))

    results.append('')

    results.append('     {} total cluster(s) found.'.format(len(data['Services'])))

    return '\n'.join(results)
