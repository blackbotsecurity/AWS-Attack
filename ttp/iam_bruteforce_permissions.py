#!/usr/bin/env python3
import datetime


# 'description': "This module will automatically run through all possible API calls of supported services in order to enumerate permissions without the use of the IAM API.",
import argparse
import json
import os
import re
import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import ParamValidationError
import importlib


target = ''

technique_info = {
    'blackbot_id': 'T1526.b.002',
    'external_id': '',
    'controller': 'iam_build_service_list',
    'services': ['all'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--services', '--get-evidence-from'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'name' : 'Cloud Service Discovery: Cloud Service Permissions' ,
    'intent': 'Enumerates permissions using brute force',

}


parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])
parser.add_argument('--get-evidence-from', required=True, help='iam_build_service_list')
parser.add_argument(
    '--services',
    required=False,
    default=None,
    help='A comma separated list of services to brute force permissions'
)


def main(args, awsattack_main):
    args = parser.parse_args(args)

    if args.get_evidence_from != 'iam_build_service_list':
        awsattack_main.print('USAGE ERROR: Invalid ttp.\n')
        return None

    command = f'run {args.get_evidence_from}'.split(' ')
    data = awsattack_main.exec_technique(command, chain=True)

    import_path = 'ttp.src.iam_bruteforce_permissions_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=data)

def print_permissions(permission_dict):
    """Helper function to print permissions."""
    for service in permission_dict:
        print('  {}:'.format(service))
        for action in permission_dict[service]:
            print('    {}'.format(action))
        print('')




def summary(data, awsattack_main):
    out = 'Services: \n'
    out += '  Supported: {}.\n'.format(data['services'])
    if 'unsupported' in data:
        out += '  Unsupported: {}.\n'.format(data['unsupported'])
    if 'unknown' in data:
        out += '  Unknown: {}.\n'.format(data['unknown'])
    return out
