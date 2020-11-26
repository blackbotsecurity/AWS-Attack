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
    'controller': 's3_enum_bucket',
    'services': ['S3'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--dl-all', '--names-only', '--dl-names'],
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

parser.add_argument('--dl-all', required=False, action='store_true', help='If specified, automatically download all files from buckets that are allowed instead of asking for each one. WARNING: This could mean you could potentially be downloading terrabytes of data! It is suggested to user --names-only and then --dl-names to download specific files.')
parser.add_argument('--names-only', required=False, action='store_true', help='If specified, only pull the names of files in the buckets instead of downloading. This can help in cases where the whole bucket is a large amount of data and you only want to target specific files for download. This option will store the filenames in a .txt file in ./sessions/[current_session_name]/downloads/s3__download_bucket/s3__download_bucket_file_names.txt, one per line, formatted as "filename@bucketname". These can then be used with the "--dl-names" option.')
parser.add_argument('--dl-names', required=False, default=False, help='A path to a file that includes the only files to be downloaded, one per line. The format for these files must be "filename.ext@bucketname", which is what the --names-only argument outputs.')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.s3_enum_bucket_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=technique_info)

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
