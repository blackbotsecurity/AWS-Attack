#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import time
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1562.b.008',
    'external_id': '',
    'controller': 'ec2_check_termination_protection',
    'services': ['EC2'],
    'prerequisite_modules': ['ec2_enum_instances'],
    'arguments_to_autocomplete': ['--instances'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Collects a list of EC2 instances without termination protection.',
    'name': 'ADD_NAME_HERE' ,

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--instances', required=False, default=None, help='A comma separated list of EC2 instances and their regions in the format instanceid@region. The default is to target all instances.')


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()
    args = parser.parse_args(args)
    fetch_data = awsattack_main.fetch_data
    
    # fetch_data is used when there is a prerequisite module to the current module. The example below shows how to fetch all EC2 security group data to use in this module.
    if fetch_data(['EC2', 'Instances'], technique_info['prerequisite_modules'][0], '--instances') is False:
        print('Pre-req module not run successfully. Exiting...')
        return None
    instances = session.EC2['Instances']

    import_path = 'ttp.src.ec2_check_termination_protection_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=instances)


def summary(data, awsattack_main):
    out = '  {} instances have termination protection disabled\n'.format(data['instance_count'])
    if data['instance_count'] > 0:
        out += '  Identified instances have been written to:\n'
        out += '     {}\n'.format(data['csv_file_path'])
    return out
