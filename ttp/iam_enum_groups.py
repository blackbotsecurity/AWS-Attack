#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1087',
    'external_id': '',
    'controller': 'iam_enum_groups',
    'services': ['IAM'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': [],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Enumerates users, roles, customer-managed policies, and groups.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.iam_enum_groups_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)


def summary(data, awsattack_main):
    out = ''
    for key in data:
        out += '  {} {} Enumerated\n'.format(data[key], key)
    out += '  IAM resources saved in AWSc2 database.\n'
    return out
