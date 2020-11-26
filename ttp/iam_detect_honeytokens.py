#!/usr/bin/env python3
import datetime

import argparse
import re
from botocore.exceptions import ClientError
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 'iam_detect_honeytokens',
    'services': ['IAM', 'SDB'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--region'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Checks if the active set of keys are known to be honeytokens.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--region', required=False, default='us-east-1', help='If for some reason you want to target a specific region for the SimpleDB API call. This shouldn\'t ever matter, because the API call is not logged to CloudTrail. The default is "us-east-1".')


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    args = parser.parse_args(args)

    import_path = 'ttp.src.iam_detect_honeytokens_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)


def summary(data, awsattack_main):
    out = ''
    if 'summary' in data.keys():
        out += '  {}\n'.format(data['summary'])
    if 'arn' in data.keys():
        out += '\n  Full ARN for the active keys (saved to database as well):\n\n    {}\n\n'.format(data['arn'])
    return out
