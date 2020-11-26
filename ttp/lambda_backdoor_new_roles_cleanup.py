#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import subprocess
import random
import string
import os
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1098.b.005',
    'external_id': '',
    'controller': 'lambda_backdoor_new_roles_cleanup',
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
    'intent': 'Creates a Lambda function and CloudWatch Events rule to backdoor new IAM roles.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.lambda_backdoor_new_roles_cleanup_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=technique_info)


def summary(data, awsattack_main):
    if data.get('cleanup'):
        return '  Completed cleanup of Lambda functions and CloudWatch Events rules.'

    return '  Lambda functions created: {}\n  CloudWatch Events rules created: {}\n  Successful backdoor deployments: {}\n'.format(data['functions_created'], data['rules_created'], data['successes'])
