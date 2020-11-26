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


    ec2_data = deepcopy(session.EC2)
    if 'Snapshots' not in ec2_data.keys():
        ec2_data['Snapshots'] = []
    session.update(awsattack_main.database, EC2=ec2_data)

    if args.regions is None:
        regions = get_regions('ec2')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')


    account_ids = args.account_ids.split(',')

    client = awsattack_main.get_boto3_client('ec2', random.choice(regions))

    now = time.time()

    summary_data = {}
    all_snaps = []
    snapshots_csv_data = []
    snapshot_permissions = {
        'Public': [],
        'Shared': {},
        'Private': []
    }
    for region in regions:
        print('Starting region {} (this may take a while if there are thousands of EBS volumes/snapshots)...'.format(region))
        client = awsattack_main.get_boto3_client('ec2', region)

        # Start EBS Snapshots in this region
        count = 0
        response = None
        next_token = False

        while (response is None or 'NextToken' in response):
            if next_token is False:
                try:
                    response = client.describe_snapshots(
                        OwnerIds=account_ids,
                        MaxResults=1000  # Using this as AWS can timeout the connection if there are too many snapshots to return in one
                    )
                except ClientError as error:
                    code = error.response['Error']['Code']
                    print('FAILURE: ')
                    if code == 'UnauthorizedOperation':
                        print('  Access denied to DescribeSnapshots.')
                    else:
                        print('  ' + code)
                    print('Skipping snapshot enumeration...')
                    break
            else:
                response = client.describe_snapshots(
                    OwnerIds=account_ids,
                    NextToken=next_token,
                    MaxResults=1000
                )

            if 'NextToken' in response:
                next_token = response['NextToken']

            for snapshot in response['Snapshots']:
                snapshot['Region'] = region

                if args.snapshot_permissions:
                    print('    Starting enumeration for Snapshot Permissions...')
                    snapshot['CreateVolumePermissions'] = client.describe_snapshot_attribute(
                        Attribute='createVolumePermission',
                        SnapshotId=snapshot['SnapshotId']
                    )['CreateVolumePermissions']

                    if not snapshot['CreateVolumePermissions']:
                        snapshot_permissions['Private'].append(snapshot['SnapshotId'])
                    elif 'UserId' in snapshot['CreateVolumePermissions'][0]:
                        snapshot_permissions['Shared'][snapshot['SnapshotId']] = [entry['UserId'] for entry in snapshot['CreateVolumePermissions']]
                    elif 'Group' in snapshot['CreateVolumePermissions'][0]:
                        snapshot_permissions['Public'].append(snapshot['SnapshotId'])

                all_snaps.append(snapshot)
                if snapshot['Encrypted'] is False:
                    name = ''
                    if 'Tags' in snapshot:
                        for tag in snapshot['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    snapshots_csv_data.append('{},{},{}\n'.format(name, snapshot['SnapshotId'], region))

            count += len(response['Snapshots'])

        print('    {} snapshot(s) found'.format(count))

    summary_data = {'snapshot_permissions': args.snapshot_permissions}

    ec2_data['Snapshots'] = all_snaps
    summary_data['snapshots'] = len(ec2_data['Snapshots'])
    unencrypted_snapshots_csv_path = 'sessions/{}/downloads/unencrypted_ebs_snapshots_{}.csv'.format(session.name, now)
    with open(unencrypted_snapshots_csv_path, 'w+') as unencrypted_snapshots_csv:
        unencrypted_snapshots_csv.write('Snapshot Name,Snapshot ID,Region\n')
        print('  Writing data for {} snapshots...'.format(len(snapshots_csv_data)))
        for line in snapshots_csv_data:
            unencrypted_snapshots_csv.write(line)
    summary_data['snapshots_csv_path'] = unencrypted_snapshots_csv_path

    if args.snapshot_permissions:
        permission_data = {
            'Public': len(snapshot_permissions['Public']),
            'Shared': len(snapshot_permissions['Shared']),
            'Private': len(snapshot_permissions['Private']),
        }
        temp = permission_data.copy()
        summary_data.update(temp)
        path = os.path.join(os.getcwd(), 'sessions', session.name, 'downloads', 'snapshot_permissions_' + str(now) + '.txt')
        with open(path, 'w') as out_file:
            out_file.write('Public:\n')
            for public in snapshot_permissions['Public']:
                out_file.write('    {}'.format(public))
            out_file.write('Shared:\n')
            for snap in snapshot_permissions['Shared']:
                out_file.write('    {}\n'.format(snap))
                for aws_id in snapshot_permissions['Shared'][snap]:
                    out_file.write('        {}\n'.format(aws_id))
            out_file.write('Private:\n')
            for private in snapshot_permissions['Private']:
                out_file.write('    {}\n'.format(private))
            summary_data['snapshot-permissions-path'] = path
    
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
