#!/usr/bin/env python3
#'description': ''The module is used to enumerate the following EC2 data from a set of regions on an AWS account: instances, security groups, elastic IP addresses, VPN customer gateways, dedicated hosts, network ACLs, NAT gateways, network interfaces, route tables, subnets, VPCs, and VPC endpoints. By default, all data will be enumerated, but if any arguments are passed in indicating what data to enumerate, only that specific data will be enumerated.',

import datetime
import argparse
from copy import deepcopy
from random import choice
from botocore.exceptions import ClientError
from core.secretfinder.utils import regex_checker, Color

ARG_FIELD_MAPPER = {
    'instances': 'Instances',
    'security_groups': 'SecurityGroups',
    'elastic_ips': 'ElasticIPs',
    'customer_gateways': 'VPNCustomerGateways',
    'dedicated_hosts': 'DedicatedHosts',
    'network_acls': 'NetworkACLs',
    'nat_gateways': 'NATGateways',
    'network_interfaces': 'NetworkInterfaces',
    'route_tables': 'RouteTables',
    'subnets': 'Subnets',
    'vpcs': 'VPCs',
    'vpc_endpoints': 'VPCEndpoints',
    'launch_templates': 'LaunchTemplates',
}

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    if args.regions is None:
        regions = get_regions('ec2')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')

    client = awsattack_main.get_boto3_client('ec2', choice(regions))

    failed = False
    all_elastic_ips = []
    for region in regions:
        elastic_ips = []

        print('Starting region {}...'.format(region))
        client = awsattack_main.get_boto3_client('ec2', region)

        try:
            response = client.describe_addresses()
            for ip in response['Addresses']:
                ip['Region'] = region
                elastic_ips.append(ip)
        except ClientError as error:
            code = error.response['Error']['Code']
            print('FAILURE: ')
            if code == 'UnauthorizedOperation':
                print('  Access denied to DescribeAddresses.')
            else:
                print('  ' + code)
            print('    Skipping elastic IP enumeration...')
            failed = True
        print('  {} elastic IP address(es) found.'.format(len(elastic_ips)))
        all_elastic_ips += elastic_ips

    gathered_data = {
        'ElasticIPs': all_elastic_ips,
    }

    for var in vars(args):
        if var == 'regions':
            continue
        if not getattr(args, var):
            del gathered_data[ARG_FIELD_MAPPER[var]]

    ec2_data = deepcopy(session.EC2)
    for key, value in gathered_data.items():
        ec2_data[key] = value
    session.update(awsattack_main.database, EC2=ec2_data)

    # Add regions to gathered_data for summary output
    gathered_data['regions'] = regions

    if not failed:
        return gathered_data
    else:
        print('No data successfully enumerated.\n')
        return None

def scan_tags(instance):
    try:
        tags = instance['Tags']
        [Color.print(Color.GREEN, '\tTag discovered {}: {}'.format(tag["Key"], tag["Value"] )) for tag in tags if regex_checker(tag['Value'])]

    except KeyError:
        return

def summary(data, awsattack_main):
    results = []

    results.append('  Regions:')
    for region in data['regions']:
        results.append('     {}'.format(region))

    results.append('')

    if 'Instances' in data:
        results.append('    {} total instance(s) found.'.format(len(data['Instances'])))

    if 'SecurityGroups' in data:
        results.append('    {} total security group(s) found.'.format(len(data['SecurityGroups'])))

    if 'ElasticIPs' in data:
        results.append('    {} total elastic IP address(es) found.'.format(len(data['ElasticIPs'])))

    if 'VPNCustomerGateways' in data:
        results.append('    {} total VPN customer gateway(s) found.'.format(len(data['VPNCustomerGateways'])))

    if 'DedicatedHosts' in data:
        results.append('    {} total dedicated hosts(s) found.'.format(len(data['DedicatedHosts'])))

    if 'NetworkACLs' in data:
        results.append('    {} total network ACL(s) found.'.format(len(data['NetworkACLs'])))

    if 'NATGateways' in data:
        results.append('    {} total NAT gateway(s) found.'.format(len(data['NATGateways'])))

    if 'NetworkInterfaces' in data:
        results.append('    {} total network interface(s) found.'.format(len(data['NetworkInterfaces'])))

    if 'RouteTables' in data:
        results.append('    {} total route table(s) found.'.format(len(data['RouteTables'])))

    if 'Subnets' in data:
        results.append('    {} total subnets(s) found.'.format(len(data['Subnets'])))

    if 'VPCs' in data:
        results.append('    {} total VPC(s) found.'.format(len(data['VPCs'])))

    if 'VPCEndpoints' in data:
        results.append('    {} total VPC endpoint(s) found.'.format(len(data['VPCEndpoints'])))

    if 'LaunchTemplates' in data:
        results.append('    {} total launch template(s) found.'.format(len(data['LaunchTemplates'])))

    return '\n'.join(results)
