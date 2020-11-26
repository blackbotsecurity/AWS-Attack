#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
import time
import random
import os

from botocore.exceptions import ClientError


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    key_info = awsattack_main.key_info
    get_regions = awsattack_main.get_regions
    ######

    ec2_data = deepcopy(session.EC2)
    if 'Volumes' not in ec2_data.keys():
        ec2_data['Volumes'] = []
    session.update(awsattack_main.database, EC2=ec2_data)

    if args.regions is None:
        regions = get_regions('ec2')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    client = awsattack_main.get_boto3_client('ec2', random.choice(regions))

    now = time.time()

    all_vols = []
    volumes_csv_data = []
    summary_data = {}
    
    for region in regions:
        print('Starting region {} (this may take a while if there are thousands of EBS volumes/snapshots)...'.format(region))
        client = awsattack_main.get_boto3_client('ec2', region)

        # Start EBS Volumes in this region
        count = 0
        response = None
        next_token = False

        while (response is None or 'NextToken' in response):
            if next_token is False:
                try:
                    response = client.describe_volumes(
                        MaxResults=500  # Using this as AWS can timeout the connection if there are too many volumes to return in one
                    )
                except ClientError as error:
                    code = error.response['Error']['Code']
                    print('FAILURE: ')
                    if code == 'UnauthorizedOperation':
                        print('  Access denied to DescribeVolumes.')
                    else:
                        print('  ' + code)
                    print('Skipping volume enumeration...')
                    break
            else:
                response = client.describe_volumes(
                    MaxResults=500,
                    NextToken=next_token
                )

            if 'NextToken' in response:
                next_token = response['NextToken']

            for volume in response['Volumes']:
                volume['Region'] = region
                all_vols.append(volume)
                if volume['Encrypted'] is False:
                    name = ''
                    if 'Tags' in volume:
                        for tag in volume['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    volumes_csv_data.append('{},{},{}\n'.format(name, volume['VolumeId'], region))

            count += len(response['Volumes'])

        print('    {} volume(s) found'.format(count))

    ec2_data['Volumes'] = all_vols
    summary_data['volumes'] = len(ec2_data['Volumes'])
    unencrypted_volumes_csv_path = 'sessions/{}/downloads/unencrypted_ebs_volumes_{}.csv'.format(session.name, now)
    
    with open(unencrypted_volumes_csv_path, 'w+') as unencrypted_volumes_csv:
        unencrypted_volumes_csv.write('Volume Name,Volume ID,Region\n')
        print('  Writing data for {} volumes...'.format(len(volumes_csv_data)))
        for line in volumes_csv_data:
            unencrypted_volumes_csv.write(line)
    
    summary_data['volumes_csv_path'] = unencrypted_volumes_csv_path

    session.update(awsattack_main.database, EC2=ec2_data)

    return summary_data


def summary(data, awsattack_main):
    out = ''
    if 'volumes' in data:
        out += '  {} Volumes found\n'.format(data['volumes'])
    if 'snapshots' in data:
        out += '  {} Snapshots found\n'.format(data['snapshots'])
    if 'volumes_csv_path' in data:
        out += '  Unencrypted volume information written to:\n    {}\n'.format(data['volumes_csv_path'])
    if 'snapshots_csv_path' in data:
        out += '  Unencrypted snapshot information written to:\n    {}\n'.format(data['snapshots_csv_path'])
    if data['snapshot_permissions']:
        out += '  Snapshot Permissions: \n'
        out += '    {} Public snapshots found\n'.format(data['Public'])
        out += '    {} Private snapshots found\n'.format(data['Private'])
        out += '    {} Shared snapshots found\n'.format(data['Shared'])
        out += '      Snapshot permissions information written to: {}\n'.format(data['snapshot-permissions-path'])
    return out
