#!/usr/bin/env python3
import datetime

import argparse
import base64
import os
import gzip
import importlib

from botocore.exceptions import ClientError
from core.secretfinder.utils import regex_checker, Color

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 'ec2_download_userdata_protection',
    'services': ['EC2'],
    'prerequisite_modules': ['ec2_enum_launchtemplates'],
    'arguments_to_autocomplete': [],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Downloads User Data from EC2 instances/launch templates.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--template-ids', required=False, default=None, help='One or more (comma separated) EC2 launch template IDs with their regions in the format template_id@region. Defaults to all EC2 launch templates in the database.')

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.ec2_download_userdata_templates_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=technique_info)

def summary(data, awsattack_main):
    session = awsattack_main.get_active_session()
    out = '  Downloaded EC2 User Data for {} launch template(s) to ./sessions/{}/downloads/ec2_user_data/.\n'.format(data['template_downloads'], session.name)
    return out
