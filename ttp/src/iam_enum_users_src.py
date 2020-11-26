#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    summary_data = {}
    client = awsattack_main.get_boto3_client('iam')

    users = []
    response = None
    is_truncated = False

    try:
        while response is None or is_truncated is True:
            if is_truncated is False:
                response = client.list_users()

            else:
                response = client.list_users(
                    Marker=response['Marker']
                )

            for user in response['Users']:
                users.append(user)

            is_truncated = response['IsTruncated']

        print('Found {} users'.format(len(users)))
    except ClientError:
        print('No Users Found')
        print('  FAILURE: MISSING NEEDED PERMISSIONS')

    iam_data = deepcopy(session.IAM)
    iam_data['Users'] = users
    session.update(awsattack_main.database, IAM=iam_data)
    summary_data['Users'] = len(users)

    return summary_data


def summary(data, awsattack_main):
    out = ''
    for key in data:
        out += '  {} {} Enumerated\n'.format(data[key], key)
    out += '  IAM resources saved in AWSc2 database.\n'
    return out
