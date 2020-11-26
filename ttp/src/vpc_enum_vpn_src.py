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
        'VPNs': 0,
    }
    for region in regions:
        print('Starting region {}...'.format(region))
        summary_data[region] = {}

        print("  Enumerating VPNs")
        # Now we look for VPN Connections
        try:
            ec2_client = awsattack_main.get_boto3_client('ec2', region)
            vpn_response = ec2_client.describe_vpn_connections()
            if 'VpnConnections' in vpn_response:
                vpn_count = len(vpn_response['VpnConnections'])
                summary_data[region]['VPNs'] = vpn_count
                summary_data['VPNs'] += vpn_count
                for vpn in vpn_response['VpnConnections']:
                    vgw_id = vpn['VpnGatewayId']
                    if vgw_id in vgw_assoc:
                        vpc_data = vgw_assoc[vgw_id]
                    else:
                        vgw_attachment, vpc_data = get_vpc_by_vgw(awsattack_main, vgw_id, region)
                    if vpc_data is not None:
                        vpc_id = vpc_data['VpcId']
                        if vpc_id not in vpcs_by_id:
                            vpcs_by_id[vpc_id] = {}
                            vpcs_found += 1
                        vpcs_by_id[vpc_id]['VPC'] = vpc_data
                        vpcs_by_id[vpc_id]['VPN'] = vpn
                        vpcs_by_id[vpc_id]['VGW'] = vgw_attachment
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

def get_vpc_by_vgw(awsattack_main, vgw_id, vgw_region):
    ec2_client = awsattack_main.get_boto3_client('ec2', vgw_region)
    vgw_response = ec2_client.describe_vpn_gateways(VpnGatewayIds=[vgw_id])
    if 'VpnGateways' in vgw_response and vgw_response['VpnGateways']:
        for vgw_attachment in vgw_response['VpnGateways'][0]['VpcAttachments']:
            vpc_id = vgw_attachment['VpcId']
            vpc_response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
            return(vgw_attachment, vpc_response['Vpcs'][0])
