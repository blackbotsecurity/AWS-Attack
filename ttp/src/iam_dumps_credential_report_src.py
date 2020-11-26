#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import os
import time

def main(args, awsattack_main, data=None):
    session = awsattack_main.get_active_session()
    report = data['Report']

    print = awsattack_main.print

    summary_data = {}
    if report and 'Content' in report:


        if not os.path.exists('sessions/{}/downloads'.format(session.name)):
            os.makedirs('sessions/{}/downloads'.format(session.name))

        filename = 'sessions/{}/downloads/get_credential_report_{}.csv'.format(session.name, time.time())
        with open(filename, 'w+') as csv_file:
            csv_file.write(report['Content'].decode())
        summary_data['report_location'] = filename

        print('Credential report saved to {}'.format(filename))

    else:
        print('\n  Unable to generate report.')

    return summary_data

