#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
import time

from botocore.exceptions import ClientError

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions
    if not args.regions:
        regions = get_regions('elasticloadbalancing')
    else:
        regions = args.regions.split(',')
    summary_data = {'load_balancers': 0}
    if 'LoadBalancers' not in session.EC2.keys():
        ec2_data = deepcopy(session.EC2)
        ec2_data['LoadBalancers'] = []
        session.update(awsattack_main.database, EC2=ec2_data)

    load_balancers = list()
    for region in regions:
        print('Starting region {}...'.format(region))
        client = awsattack_main.get_boto3_client('elbv2', region)

        count = 0
        response = None
        next_marker = False

        while (response is None or 'NextMarker' in response):
            try:
                if next_marker is False:
                    response = client.describe_load_balancers()
                else:
                    response = client.describe_load_balancers(Marker=next_marker)

                if 'NextMarker' in response:
                    next_marker = response['NextMarker']
                for load_balancer in response['LoadBalancers']:
                    load_balancer['Region'] = region
                    # Adding Attributes to current load balancer database
                    load_balancer['Attributes'] = client.describe_load_balancer_attributes(
                        LoadBalancerArn=load_balancer['LoadBalancerArn']
                    )['Attributes']
                    load_balancers.append(load_balancer)
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDenied':
                    print('  FAILURE: MISSING REQUIRED AWS PERMISSIONS')
                else:
                    print('  {}'.format(error.response['Error']['Code']))
                break
            if response and 'LoadBalancers' in response:
                count += len(response['LoadBalancers'])
        summary_data['load_balancers'] += count
        print('  {} load balancer(s) found '.format(count))

    ec2_data = deepcopy(session.EC2)
    ec2_data['LoadBalancers'] = deepcopy(load_balancers)
    session.update(awsattack_main.database, EC2=ec2_data)

    print('\n{} total load balancer(s) found.'.format(len(session.EC2['LoadBalancers'])))

    now = time.time()
    csv_file_path = 'sessions/{}/downloads/elbs_no_logs_{}.csv'.format(session.name, now)
    summary_data['csv_file_path'] = csv_file_path
    summary_data['logless'] = 0

    with open(csv_file_path, 'w+') as csv_file:
        csv_file.write('Load Balancer Name,Load Balancer ARN,Region\n')
        for load_balancer in session.EC2['LoadBalancers']:
            for attribute in load_balancer['Attributes']:
                if attribute['Key'] == 'access_logs.s3.enabled':
                    if attribute['Value'] is False or attribute['Value'] == 'false':
                        csv_file.write('{},{},{}\n'.format(load_balancer['LoadBalancerName'], load_balancer['LoadBalancerArn'], load_balancer['Region']))
                        summary_data['logless'] += 1
    return summary_data


def summary(data, awsattack_main):
    out = '  {} Load balancer(s) have been found\n'.format(data['load_balancers'])
    if data['logless'] > 0:
        out += '  {} Load balancer(s) found without logging\n'.format(data['logless'])
        out += '  List of Load balancers without logging saved to:\n    {}\n'.format(data['csv_file_path'])
    return out
