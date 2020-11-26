#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import os
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1098.b.005',
    'external_id': '',
    'controller': 'lightsail_generate_temp_access',
    'services': ['Lightsail'],
    'prerequisite_modules': ['lightsail_enum_instances'],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--instances', '--regions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Creates temporary SSH keys for available instances in AWS Lightsail.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--instances', required=False, help='One or more Lightsail instance names, their regions, and their access protocol in the format instanceid@region@protocol. Windows instances will use the RDP protocol, and others use SSH. Defaults to all instances.')
parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.lightsail_generate_temp_access_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=technique_info)


def summary(data, awsattack_main):
    out = '  Created temporary access for {} Windows instances.\n'.format(data['windows'])
    out += '  Created temporary access for {} Linux instances.\n'.format(data['linux'])
    if data['written_file_path'] is not None:
        out += '\n  Credential files written to:\n     {}{}'.format(data['written_file_path'], os.path.sep)
    return out
