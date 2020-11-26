#!/usr/bin/env python3
import datetime

import argparse
import json
import os
import re
import botocore
import importlib

from botocore.exceptions import ClientError

target = ''

technique_info = {
    'blackbot_id': 'T1069.003',
    'external_id': '',
    'controller': 'iam_enum_roles_permissions',
    'services': ['IAM'],
    'prerequisite_modules': ['iam_enum_roles'],
    'arguments_to_autocomplete': ['--role-name', '--all-roles'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Tries to get a confirmed list of permissions for the current (or all) user(s).',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--all-roles', required=False, default=False, action='store_true', help='Run this module against every role in the account and store the results to ./sessions/[current_session_name]/downloads/confirmed_permissions/role-[role_name].json. This data can then be run against the iam__privesc_scan module with the --offline flag enabled.')
parser.add_argument('--role-name', required=False, default=None, help='A single role name of a role to run this module against. By default, the active AWS keys will be used.')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.iam_enum_roles_permissions_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=technique_info) 

def summary(data, awsattack_main):
    out = ''
    if not data:
        return '  Unable to find users/roles to enumerate permissions\n'
    #if data['users_confirmed'] == 1:
    #    out += '  Confirmed permissions for user: {}.\n'.format(data['single_user'])
    #else:
    #    out += '  Confirmed permissions for {} user(s).\n'.format(data['users_confirmed'])

    if data['roles_confirmed'] == 1:
        out += '  Confirmed permissions for role: {}.\n'.format(data['single_role'])
    else:
        out += '  Confirmed permissions for {} role(s).\n'.format(data['roles_confirmed'])
    return out


