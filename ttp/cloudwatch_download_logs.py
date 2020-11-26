#!/usr/bin/env python3
import datetime

import argparse
import csv
import datetime
import os
import importlib

import pytz
from botocore.exceptions import ClientError

target = ''

technique_info = {
    'blackbot_id': 'T1530',
    'external_id': '',
    'controller': 'cloudwatch_download_logs',
    'services': ['logs'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--from-time', '--to-time'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Captures CloudWatch logs and downloads them to the session downloads folder',
    'name': '',

}

DEFAULT_FROM_TIME = pytz.utc.localize(datetime.datetime.today() - datetime.timedelta(days=1))

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])
parser.add_argument(
    '--from-time',
    required=False,
    default=DEFAULT_FROM_TIME,
    help='Download logs from time format "yyyy[-mm[-dd-[hh-mm-ss]]]". Unfilled fields will assume earliest possible time'
)
parser.add_argument(
    '--to-time',
    required=False,
    default=None,
    help='Download logs up to and not including time format "yyyy[-mm[-dd-[hh-mm-ss]]]". Unfilled fields will assume earliest possible time'
)


def parse_time(time):
    time_fields = [int(field) for field in time.split('-')]
    # Fill missing month and day.
    if len(time_fields) == 1:
        time_fields.append(1)
        time_fields.append(1)
    # Fill missing day.
    elif len(time_fields) == 2:
        time_fields.append(1)
    return pytz.utc.localize(datetime.datetime(*time_fields))

def main(args, awsattack_main):
    args = parser.parse_args(args)
    to_time = None
    
    if isinstance(args.from_time, str):
        from_time = parse_time(args.from_time)
    else:
        from_time = DEFAULT_FROM_TIME
    if isinstance(args.to_time, str):
        to_time = parse_time(args.to_time)

    scan_time = int(datetime.datetime.now().timestamp())
    args = [from_time, to_time, scan_time]

    import_path = 'ttp.src.cloudwatch_download_logs_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)


def summary(data, awsattack_main):
    out = ''
    if 'log_download_path' in data:
        out += 'Logs downloaded to: {}\n'.format(data['log_download_path'])
        del data['log_download_path']
    for region in data:
        out += '  {}:\n'.format(region)
        for key in data[region]:
            out += '    {}:{}\n'.format(key, data[region][key])
    return out
