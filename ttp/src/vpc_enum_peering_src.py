#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
from botocore.exceptions import ClientError

# Main is the first function that is called when this module is executed
def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    regions = get_regions('DirectConnect')

    # Insert all VPCs into a dict indexed by ID for deduplication.
    vpcs_by_id = dict()
    if 'VPC' in session.VPC.keys():
        for vpc in session.VPC['VPC']:
            if 'VPC' in vpc.keys():
                vpcs_by_id[vpc['VPC']['VpcId']] = deepcopy(vpc)

    vpcs_found = 0
    vgw_assoc = {}
    summary_data = {
        'peerings': 0,
    }
    for region in regions:
        print('Starting region {}...'.format(region))
        summary_data[region] = {}

        print("  Enumerating Peering")
        # And now VPC Peering
        try:
            ec2_client = awsattack_main.get_boto3_client('ec2', region)
            pcx_response = ec2_client.describe_vpc_peering_connections()
            if 'VpcPeeringConnections' in pcx_response:
                peering_count = len(pcx_response['VpcPeeringConnections'])
                summary_data[region]['peerings'] = peering_count
                summary_data['peerings'] = peering_count
                for pcx in pcx_response['VpcPeeringConnections']:
                    if pcx['AccepterVpcInfo']['VpcId'] not in vpcs_by_id:
                        vpcs_by_id[pcx['AccepterVpcInfo']['VpcId']] = {}
                        # Go get the VPC data and put into results
                        vpc_data = get_vpc_by_id(awsattack_main, pcx['AccepterVpcInfo']['VpcId'], pcx['AccepterVpcInfo']['Region'])
                        if vpc_data is not None:
                            vpcs_by_id[pcx['AccepterVpcInfo']['VpcId']]['VPC'] = vpc_data
                        else:
                            vpcs_by_id[pcx['AccepterVpcInfo']['VpcId']]['VPC'] = {'VpcId': pcx['AccepterVpcInfo']['VpcId']}
                        vpcs_found += 1
                    vpcs_by_id[pcx['AccepterVpcInfo']['VpcId']]['Peering'] = pcx

                    if pcx['RequesterVpcInfo']['VpcId'] not in vpcs_by_id:
                        vpcs_by_id[pcx['RequesterVpcInfo']['VpcId']] = {}
                        # Go get the VPC data and put into results
                        vpc_data = get_vpc_by_id(awsattack_main, pcx['RequesterVpcInfo']['VpcId'], pcx['RequesterVpcInfo']['Region'])
                        if vpc_data is not None:
                            vpcs_by_id[pcx['RequesterVpcInfo']['VpcId']]['VPC'] = vpc_data
                        else:
                            vpcs_by_id[pcx['RequesterVpcInfo']['VpcId']]['VPC'] = {'VpcId': pcx['RequesterVpcInfo']['VpcId']}
                        vpcs_found += 1
                    vpcs_by_id[pcx['RequesterVpcInfo']['VpcId']]['Peering'] = pcx
        except ClientError as error:
            print('    FAILURE:')
            code = error.response['Error']['Code']
            if code == 'UnauthorizedOperation':
                print('      MISSING NEEDED PERMISSIONS')
            else:
                print('      {}'.format(code))

    vpc_data = deepcopy(session.VPC)
    vpc_data['VPC'] = list(vpcs_by_id.values())
    session.update(awsattack_main.database, VPC=vpc_data)

    return summary_data


def summary(data, awsattack_main):
    out = '  {} Direct Connect Gateways found.\n'.format(data['gateways'])
    out += '  {} VPNs found.\n'.format(data['VPNs'])
    out += '  {} Peering Connections found.\n'.format(data['peerings'])
    out += '  {} new VPCs were found.\n'.format(data.get('vpcs_found', 0))
    out += '  {} VPCs are now known.\n'.format(data['vpcs_total'])
    return out


def get_vpc_by_id(awsattack_main, vpc_id, region):
    try:
        ec2_client = awsattack_main.get_boto3_client('ec2', region)
        vpc_response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        return vpc_response['Vpcs'][0]
    except ClientError as error:
        print('  FAILURE:')
        code = error.response['Error']['Code']
        if code == 'UnauthorizedOperation':
            print('    MISSING NEEDED PERMISSIONS')
        else:
            print('    {}'.format(code))
        return None
