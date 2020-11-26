#!/usr/bin/env python3
import datetime

import argparse
from pathlib import Path
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1530',
    'external_id': '',
    'controller': 'lightsail_download_ssh_keys',
    'services': ['Lightsail'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': [],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Downloads Lightsails default SSH key pairs.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.lightsail_download_ssh_keys_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=technique_info)


def summary(data, awsattack_main):
    out = '  Keys downloaded to:\n'
    out += '    ' + data['dl_path'] + '\n'
    out += '  Downloaded Key Pairs for the following regions: \n'
    for region in sorted(data['region_key_pairs']):
        out += '    {}\n'.format(region)
    return out
