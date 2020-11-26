#!/usr/bin/env python3
#'description': ''This module adds rules to backdoor EC2 security groups. It attempts to open ingress port ranges from an IP of your choice.',
import datetime

import argparse
from botocore.exceptions import ClientError

technique_info = {
        'prerequisite_modules': ['ec2_enum_securitygroups'],
        }

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    fetch_data = awsattack_main.fetch_data
    groups = []
    summary_data = {}

    client = awsattack_main.get_boto3_client('ec2', 'us-east-1')
    
    if args.groups is not None:
        groups_and_regions = args.groups.split(',')
        for group in groups_and_regions:
            groups.append({
                'GroupName': group.split('@')[0],
                'Region': group.split('@')[1]
            })
    else:
        if fetch_data(['EC2', 'SecurityGroups'], technique_info['prerequisite_modules'][0], '--security-groups') is False:
            print('FAILURE')
            print('  Sub-module execution failed.')
            return None
        groups = session.EC2['SecurityGroups']
    
    summary_data['BackdooredCount'] = 0
    summary_data['SecGroups'] = groups
    
    return summary_data

