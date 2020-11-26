#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
from botocore.exceptions import ClientError,EndpointConnectionError

def main(args, awsattack_main, data=None):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    summary_data = {}

    print('Starting Shield...')

    try:
        client = awsattack_main.get_boto3_client('shield', 'us-east-1')

        subscription = client.get_subscription_state()

        if subscription == 'ACTIVE':
            time_period = client.describe_subscription()
            shield_data = deepcopy(session.Shield)
            shield_data['AdvancedProtection'] = True
            shield_data['StartTime'] = time_period['Subscription']['StartTime']
            shield_data['TimeCommitmentInDays'] = time_period['Subscription']['TimeCommitmentInSeconds'] / 60 / 60 / 24
            session.update(awsattack_main.database, Shield=shield_data)
            print('    Advanced (paid) DDoS protection enabled through AWS Shield.')
            print('      Subscription Started: {}\nSubscription Commitment: {} days'.format(session.Shield['StartTime'], session.Shield['TimeCommitmentInDays']))
            summary_data['ShieldSubscription'] = 'Active'
            summary_data['ShieldSubscriptionStart'] = session.Shield['StarTime']
            summary_data['ShieldSubscriptionLength'] = session.Shield['TimeCommitmentInDays']
        else:
            shield_data = deepcopy(session.Shield)
            shield_data['AdvancedProtection'] = False
            session.update(awsattack_main.database, Shield=shield_data)
            print('    Standard (default/free) DDoS protection enabled through AWS Shield.')
            summary_data['ShieldSubscription'] = 'Inactive'

    except ClientError as error:
        code = error.response['Error']['Code']
        print('  Error getting Shield info: {}\n'.format(code))
    
    return summary_data
