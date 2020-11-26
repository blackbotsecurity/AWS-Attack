#!/usr/bin/env python3
import datetime

import argparse
import base64
from botocore.exceptions import ClientError
import time
import random
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1078.004',
    'external_id': '',
    'controller': 'ec2_startup_shell_script',
    'services': ['EC2'],
    'prerequisite_modules': ['ec2_enum_instances'],
    'arguments_to_autocomplete': ['--script', '--instance-ids'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Stops and restarts EC2 instances to execute code.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--script', required=True, help='File path of the shell script to add to the EC2 instances')
parser.add_argument('--instance-ids', required=False, default=None, help='One or more (comma separated) EC2 instance IDs and their regions in the format instanceid@region. Defaults to all instances.')

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.ec2_startup_shell_script_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=technique_info)


def summary(data, awsattack_main):
    if data['Instances']:
        out = '  {} Instance(s) Modified'.format(data['Instances'])
    else:
        out = '  No Instances Modified'
    return out

