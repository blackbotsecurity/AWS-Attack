#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import os

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()
    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    created_keys = {}
    imported_keys = 0
    name = args.key_name
    regions = args.regions.split(',') if args.regions else get_regions('lightsail')

    for region in regions:
        print('Starting region {}...'.format(region))
        client = awsattack_main.get_boto3_client('lightsail', region)
        try:
            if args.import_key_file is None:
                print('  Creating new key...')
                response = client.create_key_pair(keyPairName=name)
                created_keys[region] = {
                    'name': name,
                    'private': response['privateKeyBase64'],
                    'public': response['publicKeyBase64']
                }
            else:
                print('  Importing key...')
                try:
                    with open(args.import_key_file, 'r') as key_file:
                        key = key_file.read()
                except IOError:
                    print('Error opening key file.')
                    break
                response = client.import_key_pair(keyPairName=name, publicKeyBase64=key)
                print('    Key successfully imported for {}'.format(region))
                imported_keys += 1
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDeniedException':
                print('    Unauthorized to add key pair to Lightsail.')
            elif 'already in use' in str(error):
                print('    Key name "{}" already in use.'.format(name))
                continue
            break
        except client.exceptions.InvalidInputException as error:
            print('Invalid key format provided.')
            break
    for region in created_keys:
        ssh_key_dir = os.path.join(os.getcwd(), 'sessions', session.name, 'downloads', technique_info['name'], region)
        if not os.path.exists(ssh_key_dir):
            os.makedirs(ssh_key_dir)
        private_key_file_dir = os.path.join(ssh_key_dir, created_keys[region]['name'])
        public_key_file_dir = os.path.join(ssh_key_dir, created_keys[region]['name'] + '.pub')
        try:
            with open(private_key_file_dir, 'w') as private_key_file:
                private_key_file.write(created_keys[region]['private'])
            with open(public_key_file_dir, 'w') as public_key_file:
                public_key_file.write(created_keys[region]['public'])
        except IOError:
            print('Error writing key pair {} to file'.format(created_keys[region]['name']))
            continue

    summary_data = {
        'keys': len(created_keys.keys()),
        'imports': imported_keys
    }
    return summary_data

