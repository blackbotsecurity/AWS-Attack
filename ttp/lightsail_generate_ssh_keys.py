#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import os
import importlib

target = ''

technique_info = {
    'blackbot_id': '', # Igor: I don't know what ttp id would be
    'external_id': '',
    'controller': 'lightsail_generate_ssh_keys',
    'services': ['Lightsail'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--key-name', '--import-key-file', '--regions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Creates SSH keys for available regions in AWS Lightsail.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--key-name', default='AWSc2', required=False, help='Alias for imported/created key pair. Defaults to AWSc2.')
parser.add_argument('--import-key-file', required=False, help='Import a key if specified, otherwise, create one.')
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.lightsail_generate_ssh_keys_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)


def summary(data, awsattack_main):
    if data['imports'] > 0:
        out = '  {} key(s) imported'.format(data['imports'])
    else:
        out = '  {} key(s) created'.format(data['keys'])
    return out
