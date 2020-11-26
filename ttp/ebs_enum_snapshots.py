#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
import time
import random
import os
import importlib

from botocore.exceptions import ClientError

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 'ebs_enum_snapshots',
    'services': ['EC2'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--regions', '--account-ids', '--snapshot-permissions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Enumerates EBS volumes and snapshots and logs any without encryption.',
    'name': '',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument(
    '--regions',
    required=False,
    default=None,
    help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.'
)
parser.add_argument(
    '--snapshot-permissions',
    required=False,
    default=False,
    action='store_true',
    help='Capture permissions for each found snapshot. Found permissions will be captured in the database and written to the sessions downloads directory as snapshot_permissions.txt'
)
parser.add_argument(
    '--account-ids',
    required=True,
    default=None,
    help='One or more (comma separated) AWS account IDs. If snapshot enumeration is enabled, then this module will fetch all snapshots owned by each account in this list of AWS account IDs. Defaults to the current user accounts AWS account ID.'
)



def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.ebs_enum_snapshots_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)


def summary(data, awsattack_main):
    out = ''
    if 'snapshots' in data:
        out += '  {} Snapshots found\n'.format(data['snapshots'])
    if 'snapshots_csv_path' in data:
        out += '  Unencrypted snapshot information written to:\n    {}\n'.format(data['snapshots_csv_path'])
    if data['snapshot_permissions']:
        out += '  Snapshot Permissions: \n'
        out += '    {} Public snapshots found\n'.format(data['Public'])
        out += '    {} Private snapshots found\n'.format(data['Private'])
        out += '    {} Shared snapshots found\n'.format(data['Shared'])
        out += '      Snapshot permissions information written to: {}\n'.format(data['snapshot-permissions-path'])
    return out
