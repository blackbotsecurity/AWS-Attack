#!/usr/bin/env python3
#'description': ''The module is used to enumerate the following EC2 data from a set of regions on an AWS account: instances, security groups, elastic IP addresses, VPN customer gateways, dedicated hosts, network ACLs, NAT gateways, network interfaces, route tables, subnets, VPCs, and VPC endpoints. By default, all data will be enumerated, but if any arguments are passed in indicating what data to enumerate, only that specific data will be enumerated.',

import datetime
import argparse
from copy import deepcopy
from random import choice
from botocore.exceptions import ClientError
from core.secretfinder.utils import regex_checker, Color
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1018',
    'external_id': '',
    'controller': 'ec2_enum_vpcendpoints',
    'services': ['EC2'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. ' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'name': 'Remote System Discovery',
    'intent': 'Enumerates EC2 information.',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--regions', required=False, default=None, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.ec2_enum_vpcendpoints_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

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
