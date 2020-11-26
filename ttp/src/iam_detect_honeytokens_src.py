#!/usr/bin/env python3
import datetime

import argparse
import re
from botocore.exceptions import ClientError

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print

    data = {}
    client = awsattack_main.get_boto3_client('sdb', args.region)

    print('Making test API request...\n')

    try:
        client.list_domains()

        data['summary'] = 'API call was successful! This means you have the SimpleDB ListDomains permission and we could not get your ARN from the API call.'
    except ClientError as error:
        if error.response['Error']['Code'] == 'AuthorizationFailure':
            message = error.response['Error']['Message']

            if 'canarytokens.com' in message or 'canarytokens.org' in message:
                data['summary'] = 'WARNING: Keys are confirmed honeytoken keys from Canarytokens.org! Do not use them!'
            elif 'arn:aws:iam::' in message and '/SpaceCrab/' in message:
                data['summary'] = 'WARNING: Keys are confirmed honeytoken keys from SpaceCrab! Do not use them!'
            elif 'arn:aws:iam::534261010715:' in message or 'arn:aws:sts::534261010715:' in message:
                data['summary'] = 'WARNING: Keys belong to an AWS account owned by Canarytokens.org! Do not use them!'
            else:
                data['summary'] = 'Keys appear to be real (not honeytoken keys)!'

            match = re.search(r'User \(arn:.*\) does not have permission to perform', message)
            if match:
                data['arn'] = match.group().split('(')[1].split(')')[0]

                active_aws_key = session.get_active_aws_key(awsattack_main.database)

                if ':assumed-role/' in data['arn']:
                    active_aws_key.update(
                        awsattack_main.database,
                        arn=data['arn'],
                        account_id=data['arn'].split('arn:aws:sts::')[1][:12],
                        # -2 will get the role name everytime,
                        # even if there is a role path and
                        # session name
                        role_name=data['arn'].split(':assumed-role/')[1].split('/')[-2]
                    )
                elif ':user/' in data['arn']:
                    active_aws_key.update(
                        awsattack_main.database,
                        arn=data['arn'],
                        account_id=data['arn'].split('arn:aws:iam::')[1][:12],
                        # -1 will get the user name everytime,
                        # even if there is a user path
                        user_name=data['arn'].split(':user/')[1].split('/')[-1]
                    )
        else:
            data['summary'] = '  Unhandled error received: {}'.format(error.response['Error']['Code'])

    print('  {}\n'.format(data['summary']))

    return data

