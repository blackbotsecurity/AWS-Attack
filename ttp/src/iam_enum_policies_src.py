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

    policies = []
    response = None
    is_truncated = False

    try:
        while response is None or is_truncated is True:
            if is_truncated is False:
                response = client.list_policies(
                    Scope='Local'
                )

            else:
                response = client.list_policies(
                    Scope='Local',
                    Marker=response['Marker']
                )

            for policy in response['Policies']:
                policies.append(policy)

            is_truncated = response['IsTruncated']
        print('Found {} policies'.format(len(policies)))

    except ClientError:
        print('No Policies Found')
        print('  FAILURE: MISSING NEEDED PERMISSIONS')

    iam_data = deepcopy(session.IAM)
    iam_data['Policies'] = policies
    session.update(awsattack_main.database, IAM=iam_data)
    summary_data['Policies'] = len(policies)

    return summary_data
