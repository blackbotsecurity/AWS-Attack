#!/usr/bin/env python3
import datetime

#'description': "This module examines Lightsail data fields and automatically enumerates them for all available regions. Available fields can be passed upon execution to only look at certain types of data. By default, all Lightsail fields will be captured.",

import argparse
from botocore.exceptions import ClientError
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1526.b.001',
    'external_id': '',
    'controller': 'lightsail_enum_instances',
    'services': ['Lightsail'],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Captures common data associated with Lightsail',
    'name': 'Cloud Service Discovery: Lightsail' ,
}


parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.lightsail_enum_instances_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = '  Regions Enumerated:\n'
    for region in data['regions']:
        out += '    {}\n'.format(region)
    del data['regions']
    for field in data:
        out += '  {} {} enumerated\n'.format(data[field], field[:-1] + '(s)')
    return out
