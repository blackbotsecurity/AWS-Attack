#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
from botocore.exceptions import ClientError
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1046',
    'external_id': '',
    'controller': 'vpc_enum_directconnect',
    'services': ['EC2', 'DirectConnect'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--versions-all'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Looks for Network Plane lateral movement opportunities.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])
parser.add_argument('--versions-all', required=False, default=False, action='store_true', help='Grab all versions instead of just the latest')


# Main is the first function that is called when this module is executed
def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.vpc_enum_directconnect_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = '  {} Direct Connect Gateways found.\n'.format(data['gateways'])
    out += '  {} new VPCs were found.\n'.format(data.get('vpcs_found', 0))
    out += '  {} VPCs are now known.\n'.format(data['vpcs_total'])
    return out

