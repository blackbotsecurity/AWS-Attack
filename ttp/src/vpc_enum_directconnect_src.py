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
        'gateways': 0,
    }
    for region in regions:
        print('Starting region {}...'.format(region))
        summary_data[region] = {}

        dx_client = awsattack_main.get_boto3_client('directconnect', region)

        print("  Enumerating DirectConnect")
        try:
            gw_response = dx_client.describe_direct_connect_gateways()
            if 'directConnectGateways' in gw_response:
                gateway_count = len(gw_response['directConnectGateways'])
                summary_data[region]['gateways'] = gateway_count
                summary_data['gateways'] += gateway_count
                for dx_gw in gw_response['directConnectGateways']:
                    dx_gw_id = dx_gw['directConnectGatewayId']
                    assoc_response = dx_client.describe_direct_connect_gateway_associations(directConnectGatewayId=dx_gw_id)
                    if 'directConnectGatewayAssociations' in assoc_response:
                        for dx_assoc in assoc_response['directConnectGatewayAssociations']:
                            vgw_id = dx_assoc['virtualGatewayId']
                            vgw_region = dx_assoc['virtualGatewayRegion']
                            # Apparently Direct Connects work across region
                            # The Gateway can be in Virgina, but the VGW in Ohio.
                            vgw_attachment, vpc_data = get_vpc_by_vgw(awsattack_main, vgw_id, vgw_region)
                            if vpc_data is not None:
                                # Ok, if we get here, we have a active DX VPC and opportunities for more exploration
                                # for analysis, we bundle up all the data, and key it off the VPC_ID
                                vpcs_by_id[vpc_data['VpcId']] = {
                                    'VPC': vpc_data,
                                    'VGW': vgw_attachment,
                                    'DirectConnectAssociation': dx_assoc,
                                    'DirectConnectGateway': dx_gw,
                                }
                                if vpc_data['VpcId'] not in vpcs_by_id:
                                    vpcs_found += 1
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

    summary_data.update({
        'vpcs_found': vpcs_found,
        'vpcs_total': len(session.VPC)
    })
    return summary_data

def get_vpc_by_vgw(awsattack_main, vgw_id, vgw_region):
    ec2_client = awsattack_main.get_boto3_client('ec2', vgw_region)
    vgw_response = ec2_client.describe_vpn_gateways(VpnGatewayIds=[vgw_id])
    if 'VpnGateways' in vgw_response and vgw_response['VpnGateways']:
        for vgw_attachment in vgw_response['VpnGateways'][0]['VpcAttachments']:
            vpc_id = vgw_attachment['VpcId']
            vpc_response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
            return(vgw_attachment, vpc_response['Vpcs'][0])

