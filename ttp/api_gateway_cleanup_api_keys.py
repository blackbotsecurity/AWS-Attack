#!/usr/bin/env python3
#'description': ''This module automatically creates API keys for every available region. There is an included cleanup feature to remove old "AWSc2" keys that are referenced by name.',
import datetime
import argparse
from copy import deepcopy
from botocore.exceptions import ClientError
import importlib

target = ''

technique_info = {
    'blackbot_id': '',
    'external_id': '',
    'controller': 'api_gateway_create_api_keys',
    'services': ['apigateway'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': ['Attempts to create an API Gateway key for any/all REST APIs within a target region.'],
    'name': 'Create or Modify Cloud Service: Create API Gateway Key' ,

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.api_gateway_cleanup_api_keys_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = ''
    if data.get('cleanup'):
        out += '  Old keys removed.\n'
    return out
