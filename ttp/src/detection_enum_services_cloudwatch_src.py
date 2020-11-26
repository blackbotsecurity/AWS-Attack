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

    print('Starting CloudWatch...')
    cw_regions = get_regions('monitoring')
    all_alarms = []
    cloudwatch_permission = True
    for region in cw_regions:
        if not cloudwatch_permission:
            print('  No Valid Permissions Found')
            print('    Skipping subsequent enumerations for remaining regions...')
            break

        print('  Starting region {}...'.format(region))
        client = awsattack_main.get_boto3_client('cloudwatch', region)
        paginator = client.get_paginator('describe_alarms')
        page_iterator = paginator.paginate()
        alarms = []
        try:
            for page in page_iterator:
                alarms.extend(page['MetricAlarms'])
            print('    {} alarms found.'.format(len(alarms)))
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDenied':
                print('    ACCESS DENIED: DescribeAlarms')
                print('      Skipping subsequent enumerations...')
                cloudwatch_permission = False
            else:
                print('    {}'.format(code))
        for alarm in alarms:
            alarm['Region'] = region
        all_alarms.extend(alarms)

    cw_data = deepcopy(session.CloudWatch)
    cw_data['Alarms'] = all_alarms
    session.update(awsattack_main.database, CloudWatch=cw_data)
    print('  {} total CloudWatch alarm(s) found.'.format(len(session.CloudWatch['Alarms'])))
    summary_data['alarms'] = len(all_alarms)

    return summary_data


