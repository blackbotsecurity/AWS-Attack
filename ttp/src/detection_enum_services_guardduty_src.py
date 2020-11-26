#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
from botocore.exceptions import ClientError,EndpointConnectionError

def main(args, awsattack_main, data=None):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    summary_data = {}
    print('Starting GuardDuty...')
    guard_duty_regions = get_regions('guardduty')
    all_detectors = []
    guard_duty_permission = True
    master_count = 0

    for region in guard_duty_regions:
        if not guard_duty_permission:
            print('  No Valid Permissions Found')
            print('    Skipping subsequent enumerations for remaining regions...')
            break
        detectors = []
        print('  Starting region {}...'.format(region))
        client = awsattack_main.get_boto3_client('guardduty', region)
        paginator = client.get_paginator('list_detectors')
        page_iterator = paginator.paginate()
        try:
            for page in page_iterator:
                for detector in page['DetectorIds']:
                    status, master = get_detector_master(detector, client)
                    detectors.append({
                        'Id': detector,
                        'Region': region,
                        'MasterStatus': status,
                        'MasterAccountId': master
                    })
                    if not master:
                        master_count += 1
            print('    {} GuardDuty Detector(s) found.'.format(len(detectors)))
            all_detectors.extend(detectors)
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDeniedException':
                print('    ACCESS DENIED: ListDetectors')
                print('       Skipping subsequent enumerations...')
                guard_duty_permission = False
            else:
                print('    {}'.format(code))
        except EndpointConnectionError as error: 
            print('    Error connecting to Guardduty Endpoint for region: {}'.format(region))
            print('        Error: {}, {}'.format(error.__class__, str(error)))
        except Exception as error: 
            print('    Generic Error when enumerating Guardduty detectors for region: {}'.format(region))
            print('        Error: {}, {}'.format(error.__class__, str(error)))

    summary_data['MasterDetectors'] = master_count
    guardduty_data = deepcopy(session.GuardDuty)
    guardduty_data['Detectors'] = all_detectors
    session.update(awsattack_main.database, GuardDuty=guardduty_data)
    print('  {} total GuardDuty Detector(s) found.\n'.format(len(session.GuardDuty['Detectors'])))
    summary_data['Detectors'] = len(session.GuardDuty['Detectors'])

    return summary_data

