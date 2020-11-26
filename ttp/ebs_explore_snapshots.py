#!/usr/bin/env python3
import datetime

"""Module for ebs_snapshot_explorer"""
import argparse
from copy import deepcopy
import json
from pathlib import Path
import importlib

from botocore.exceptions import ClientError

target = ''

technique_info = {
    'controller': 'ebs_explore_snapshots',
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Restores and attaches EBS volumes/snapshots to an EC2 instance of your choice.',
    'name': 'ADD_NAME_HERE' ,#'description': ''This module will cycle through existing EBS volumes and create snapshots of them, then restore those snapshots and existing snapshots to new EBS volumes, which will then be attached to the supplied EC2 instance for you to mount. This will give you access to the files on the various volumes, where you can then look for sensitive information. Afterwards, it will cleanup the created volumes and snapshots by detaching them from your instance and removing them from the AWS account.',
    'services': ['EC2'],
    'prerequisite_modules': ['ec2_enum_instances', 'ebs_enum_snapshots'],
    'arguments_to_autocomplete': ['--instance-id', '--zone'],
    'blackbot_id': 'T1078.004',
    'external_id': '',
    'version': '1',
    'aws_namespaces': [],

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])
parser.add_argument(
    '--instance-id',
    required=True,
    help='InstanceId of instance to target'
)
parser.add_argument(
    '--zone',
    required=True,
    help='Availability zone of instance to target'
)

SET_COUNT = 10

def main(args, awsattack):
    args = parser.parse_args(args)

    import_path = 'ttp.src.ebs_explore_snapshots_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack):
    """Returns a formatted string based on passed data."""
    out = ''
    if 'snapshots' in data:
        out += '  {} Snapshots loaded\n'.format(data['snapshots'])
    if 'volumes' in data:
        out += '  {} Volumes loaded\n'.format(data['volumes'])
    if not out:
        return '  No volumes were loaded\n'
    return out
