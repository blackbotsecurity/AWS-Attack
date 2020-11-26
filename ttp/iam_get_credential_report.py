#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import os
import time
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1087.004',
    'external_id': '',
    'controller': 'iam_get_credential_report',
    'services': ['IAM'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': [],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Generates and downloads an IAM credential report.',
    'name': 'ADD_NAME_HERE',
}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

def main(args, awsattack_main):
    args = parser.parse_args(args)
    input = awsattack_main.input

    import_path = 'ttp.src.iam_get_credential_report_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)


def summary(data, awsattack_main):
    out = ''
    if data['generated']:
        out += '  Report was generated\n'
    else:
        out += '  Report was not generated\n'
    if 'report_location' in data:
        out += '    Report saved to: {}\n'.format(data['report_location'])
    return out
