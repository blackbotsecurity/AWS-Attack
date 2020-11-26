#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import os
import time

def main(args, awsattack_main, data=None):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    input = awsattack_main.input

    client = awsattack_main.get_boto3_client('iam')
    report = None
    generated = False
    summary_data = {'generated': False}
    while True:
        try:
            report = client.get_credential_report()
            break
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'ReportNotPresent' or code == 'ReportInProgress':
                if generated or code == 'ReportInProgress':
                    generated = True
                    print('waiting...')
                    time.sleep(20)
                else:
                    try:
                        client.generate_credential_report()
                        print('  Starting. Checking completion every 20 seconds...')
                        generated = True
                        summary_data['generated'] = True
                    except ClientError as error:
                        if error.response['Error']['Code'] == 'AccessDenied':
                            print('Unauthorized to generate_credential_report')
                            report = None
                            break
            
            elif code == 'AccessDenied':
                print('  FAILURE:')
                print('    MISSING NEEDED PERMISSIONS')
                report = None
                break
            else:
                print('Unrecognized ClientError: {} ({})'.format(str(error), error.response['Error']['Code']))
                break

    if report:
        summary_data['Report'] = report
    else:
        summary_data['Report'] = None

    return summary_data

