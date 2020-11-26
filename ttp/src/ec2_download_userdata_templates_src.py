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

    templates = []
    summary_data = {'template_downloads': 0}

    if args.template_ids is not None:
        for template in args.template_ids.split(','):
            template_id, region = template.split('@')
            templates.append({
                'LaunchTemplateId': template_id,
                'Region': region
            })


    else:
        if fetch_data(['EC2', 'LaunchTemplates'], technique_info['prerequisite_modules'][0], None) is False:
            print('Pre-req module not run successfully. Exiting...')
            templates = []
        else:
            templates = session.EC2['LaunchTemplates']

    if not os.path.exists('sessions/{}/downloads/ec2_user_data/'.format(session.name)):
        os.makedirs('sessions/{}/downloads/ec2_user_data/'.format(session.name))

    if templates:
        print('Targeting {} launch template(s)...'.format(len(templates)))
        for template in templates:
            template_id = template['LaunchTemplateId']
            region = template['Region']
            client = awsattack_main.get_boto3_client('ec2', region)

            all_versions = []

            try:
                response = client.describe_launch_template_versions(
                    LaunchTemplateId=template_id
                )
                all_versions.extend(response['LaunchTemplateVersions'])
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'AccessDenied':
                    print('  Access denied to DescribeLaunchTemplateVersions.')
                    print('Skipping the rest of the launch templates...\n')
                    break
                else:
                    print('  ' + code)

            while response.get('NextToken'):
                response = client.describe_launch_template_versions(
                    LaunchTemplateId=template_id,
                    NextToken=response['NextToken']
                )
                all_versions.extend(response['LaunchTemplateVersions'])

            for version in all_versions:
                if version['LaunchTemplateData'].get('UserData'):
                    try:
                        was_unzipped = False
                        user_data = version['LaunchTemplateData']['UserData']
                        formatted_user_data = '{}-version-{}@{}:\n{}\n\n'.format(
                            template_id,
                            version['VersionNumber'],
                            region,
                            base64.b64decode(user_data).decode('utf-8')
                        )
                    except UnicodeDecodeError as error:
                        if 'codec can\'t decode byte 0x8b' in str(error):
                            decoded = base64.b64decode(user_data['Value'])
                            decompressed = gzip.decompress(decoded)
                            formatted_user_data = '{}@{}:\n{}\n\n'.format(
                                instance_id,
                                region,
                                decompressed.decode('utf-8')
                            )
                            was_unzipped = True
                    print('  {}-version-{}@{}: User Data found'.format(template_id, version['VersionNumber'], region))
                    if was_unzipped:
                        print('    Gzip decoded the User Data')

                    # Write to the "all" file
                    with open('sessions/{}/downloads/ec2_user_data/all_user_data.txt'.format(session.name), 'a+') as data_file:
                        data_file.write(formatted_user_data)
                    # Write to the individual file
                    with open('sessions/{}/downloads/ec2_user_data/{}-version-{}.txt'.format(session.name, template_id, version['VersionNumber']), 'w+') as data_file:
                        data_file.write(formatted_user_data.replace('\\t', '\t').replace('\\n', '\n').rstrip())
                    summary_data['template_downloads'] += 1
                else:
                    print('  {}-version-{}@{}: No User Data found'.format(template_id, version['VersionNumber'], region))
        print()
    else:
        print('No launch templates to target.\n')

    return summary_data

def find_secrets(userdata):
    detections = regex_checker(userdata)
    [Color.print(Color.GREEN, '\tDetected {}: {}'.format(itemkey, detections[itemkey])) for itemkey in detections]

def summary(data, awsattack_main):
    session = awsattack_main.get_active_session()
    out = '  Downloaded EC2 User Data for {} instance(s) and {} launch template(s) to ./sessions/{}/downloads/ec2_user_data/.\n'.format(data['instance_downloads'], data['template_downloads'], session.name)
    return out
