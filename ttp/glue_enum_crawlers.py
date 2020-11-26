#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy

from botocore.exceptions import ClientError
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 'glue_enum_crawlers',
    'services': ['Glue'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--regions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Enumerates Glue connections, crawlers, databases, development endpoints, and jobs.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format us-east-1. Defaults to all session regions.')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.glue_enum_crawlers_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = ''
    for key in data:
        out += '  {} total {}(s) found.\n'.format(data[key], key[:-1])
    out += '\n  Glue resources saved in AWSc2 database.\n'
    return out
