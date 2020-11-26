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
    'controller': 'lambda_backdoor_new_users_cleanup',
    'services': ['Lambda', 'Events', 'IAM'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
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

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.lambda_backdoor_new_users_cleanup_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)


def summary(data, awsattack_main):
    if data.get('cleanup'):
        return '  Completed cleanup of Lambda functions and CloudWatch Events rules.'

