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
    all_network_acls = []
    for region in regions:
        network_acls = []

        print('Starting region {}...'.format(region))
        client = awsattack_main.get_boto3_client('ec2', region)

        try:
            response = client.describe_network_acls()
            for acl in response['NetworkAcls']:
                acl['Region'] = region
                network_acls.append(acl)
        except ClientError as error:
            code = error.response['Error']['Code']
            print('FAILURE: ')
            if code == 'UnauthorizedOperation':
                print('  Access denied to DescribeNetworkACLs.')
            else:
                print('  ' + code)
            print('    Skipping network ACL enumeration...')
            failed = False
        print('  {} network ACL(s) found.'.format(len(network_acls)))
        all_network_acls += network_acls


    gathered_data = {
        'NetworkACLs': all_network_acls,
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
   
