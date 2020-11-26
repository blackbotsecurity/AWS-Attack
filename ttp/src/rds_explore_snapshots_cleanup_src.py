#!/usr/bin/env python3
import datetime

import argparse
from pathlib import Path
import json
import random
import string

from botocore.exceptions import ClientError


TEMP_FILE = Path(__file__).parent / 'temp.json'
WAIT_CONFIG = {'Delay': 10}

def read_temp():
    with TEMP_FILE.open('r') as infile:
        data = json.load(infile)
    return data

def cleanup(awsattack):
    data = read_temp()
    success = True
    for instance in data['Instances']:
        client = awsattack.get_boto3_client('rds', data['Instances'][instance]['AvailabilityZone'][:-1])
        if not delete_instance(client, instance, awsattack.print):
            success = False
    for snapshot in data['Snapshots']:
        client = awsattack.get_boto3_client('rds', data['Snapshots'][snapshot]['AvailabilityZone'][:-1])
        if not delete_snapshot(client, snapshot, awsattack.print):
            success = False
    return success


def main(args, awsattack):
    """Main module function, called from AWSc2"""
    summary_data = {}
    if args.regions:
        regions = args.regions.split(',')
    else:
        regions = awsattack.get_regions('rds')
    
    if not cleanup(awsattack):
        return {'fail': 'Failed to delete temporary data.'}
    
    summary_data['cleanup'] = 'success'
    return summary_data

def delete_snapshot(client, snapshot, print):
    waiter = client.get_waiter('db_snapshot_available')
    waiter.wait(
        DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    try:
        response = client.delete_db_snapshot(
            DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier']
        )
        remove_temp(response['DBSnapshot'])
        return True
    except ClientError as error:
        print('      ' + error.response['Error']['Code'])
    return False


def delete_instance(client, instance, print):
    waiter = client.get_waiter('db_instance_available')
    waiter.wait(
        DBInstanceIdentifier=instance['DBInstanceIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    try:
        response = client.delete_db_instance(
            DBInstanceIdentifier=instance['DBInstanceIdentifier'],
            SkipFinalSnapshot=True,
        )
        remove_temp(response['DBInstance'])
    except ClientError as error:
        print('      ' + error.response['Error']['Code'])
        return False
    waiter = client.get_waiter('db_instance_deleted')
    waiter.wait(
        DBInstanceIdentifier=instance['DBInstanceIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    return True


