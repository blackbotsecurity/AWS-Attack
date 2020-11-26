#!/usr/bin/env python3
import datetime

import argparse
import botocore
import random
import string
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1078.004',
    'external_id': '',
    'controller': 'iam_enum_guessing_roles',
    'services': ['IAM', 'STS'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--word-list', '--role-name', '--account-id'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Enumerates IAM roles in a separate AWS account, given the account ID.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--word-list', required=False, default=None, help='File path to a different word list to use. There is a default word list with 1100+ words. The word list should contain words, one on each line, to use to try and guess IAM role names. Role names ARE case-sensitive.')
parser.add_argument('--role-name', required=True, help='The name of a valid role in the current users account to try and update the AssumeRole policy document for.')
parser.add_argument('--account-id', required=True, help='The AWS account ID of the target account (12 numeric characters).')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.iam_enum_guessing_roles_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    results = []

    results.append('  {} role(s) found after {} guess(es).'.format(len(data['valid_roles']), data['attempts']))

    if len(data['valid_roles']) > 0:
        results.append('  {} out of {} enumerated role(s) successfully assumed.'.format(len(data['roles_assumed']), len(data['valid_roles'])))

    return '\n'.join(results)
