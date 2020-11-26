#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
from botocore.exceptions import ClientError,EndpointConnectionError

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    summary_data = {}

    print('Starting VPC...')
    vpc_regions = get_regions('ec2')
    all_flow_logs = []
    flow_log_permission = True

    for region in vpc_regions:
        if not flow_log_permission:
            print('  No Valid Permissions Found')
            print('    Skipping subsequent enumerations for remaining regions...')
            break
        print('  Starting region {}...'.format(region))

        client = awsattack_main.get_boto3_client('ec2', region)
        kwargs = {'MaxResults': 1000}
        flow_logs = []
        while True:
            try:
                response = client.describe_flow_logs(**kwargs)
            except ClientError as error:
                code = error.response['Error']['Code']
                if code == 'UnauthorizedOperation':
                    print('    ACCESS DENIED: DescribeFlowLogs')
                    print('      Skipping subsequent enumerations...')
                    flow_log_permission = False
                else:
                    print('    {}'.format(code))
                break
            flow_logs.extend(response['FlowLogs'])
            if 'NextToken' in response:
                kwargs['NextToken'] = response['NextToken']
            else:
                print('    {} flow log(s) found.'.format(len(flow_logs)))
                break
        for flow_log in flow_logs:
            flow_log['Region'] = region

        all_flow_logs.extend(flow_logs)

    vpc_data = deepcopy(session.VPC)
    vpc_data['FlowLogs'] = all_flow_logs
    session.update(awsattack_main.database, VPC=vpc_data)
    print('  {} total VPC flow log(s) found.'.format(len(session.VPC['FlowLogs'])))
    summary_data['flowlogs'] = len(all_flow_logs)

    return summary_data


