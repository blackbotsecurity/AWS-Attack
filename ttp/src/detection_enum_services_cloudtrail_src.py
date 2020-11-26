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
    
    print('Starting CloudTrail...')
    cloudtrail_regions = get_regions('cloudtrail')
    all_trails = []
    cloudtrail_permission = True
    for region in cloudtrail_regions:
        if not cloudtrail_permission:
            print('  No Valid Permissions Found')
            print('    Skipping subsequent enumerations for remaining regions...')
            break
        print('  Starting region {}...'.format(region))

        client = awsattack_main.get_boto3_client('cloudtrail', region)
        try:
            trails = client.describe_trails(includeShadowTrails=False)
            for trail in trails['trailList']:
                trail['Region'] = region
                all_trails.append(trail)
            print('    {} trail(s) found.'.format(len(trails['trailList'])))
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDeniedException':
                print('    ACCESS DENIED: DescribeTrails')
                print('       Skipping subsequent enumerations...')
                cloudtrail_permission = False
            else:
                print('    {}'.format(code))

    cloudtrail_data = deepcopy(session.CloudTrail)
    cloudtrail_data['Trails'] = all_trails
    session.update(awsattack_main.database, CloudTrail=cloudtrail_data)
    print('  {} total CloudTrail trail(s) found.'.format(len(session.CloudTrail['Trails'])))
    summary_data['CloudTrails'] = len(session.CloudTrail['Trails'])
    
    return summary_data

