#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import time

def main(args, awsattack_main, data=None):
    session = awsattack_main.get_active_session()
    print = awsattack_main.print
    summary_data = {'instance_count': 0}
    instances = data 
    now = time.time()
    csv_file_path = 'sessions/{}/downloads/termination_protection_disabled_{}.csv'.format(session.name, now)

    summary_data['csv_file_path'] = csv_file_path
    with open(csv_file_path, 'w+') as csv_file:
        csv_file.write('Instance Name,Instance ID,Region\n')
        
        for instance in instances:
            client = awsattack_main.get_boto3_client('ec2', instance['Region'])

            try:
                instance['TerminationProtection'] = client.describe_instance_attribute(
                    Attribute='disableApiTermination',
                    InstanceId=instance['InstanceId']
                )['DisableApiTermination']['Value']
                if instance['TerminationProtection'] is False:
                    name = ''
                    if 'Tags' in instance:
                        for tag in instance['Tags']:
                            if tag['Key'] == 'Name':
                                name = tag['Value']
                                break
                    csv_file.write('{},{},{}\n'.format(name, instance['InstanceId'], instance['Region']))
                    summary_data['instance_count'] += 1
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'UnauthorizedOperation':
                    print('  Access denied to DescribeInstanceAttribute.')
                    break
                else:
                    print('  ' + code)
                print('Failed to retrieve info for instance ID {}: {}'.format(instance['InstanceId'], error))

    ec2_data = deepcopy(session.EC2)
    ec2_data['Instances'] = instances
    session.update(awsattack_main.database, EC2=ec2_data)
    return summary_data


def summary(data, awsattack_main):
    out = '  {} instances have termination protection disabled\n'.format(data['instance_count'])
    if data['instance_count'] > 0:
        out += '  Identified instances have been written to:\n'
        out += '     {}\n'.format(data['csv_file_path'])
    return out
