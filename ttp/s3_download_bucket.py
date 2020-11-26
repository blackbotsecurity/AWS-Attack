#!/usr/bin/env python3
import datetime

import argparse
import datetime
from copy import deepcopy
import os
import importlib

from botocore.exceptions import ClientError

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 's3_download_bucket',
    'services': ['S3'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--dl-names'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Enumerate and dumps files from S3 buckets.',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--dl-names', required=True, default=False, help='A path to a file that includes the only files to be downloaded, one per line. The format for these files must be "filename.ext@bucketname", which is what the --names-only argument outputs.')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.s3_download_bucket_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = ''
    if 'buckets' in data:
        out += '  {} total buckets found.\n'.format(data['buckets'])
    if 'objects' in data:
        out += '  {} \n'.format(data['buckets'])
    if 'readable_buckets' in data:
        out += '  {} buckets found with read permissions.\n'.format(data['readable_buckets'])
    if 'downloaded_files' in data:
        out += '  {} files downloaded.\n'.format(data['downloaded_files'])
    if 'failed' in data:
        out += '  {} files failed to be downloaded.\n'.format(data['failed'])
    if not out:
        return '  No actions were taken.'
    return out
