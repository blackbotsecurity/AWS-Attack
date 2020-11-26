#!/usr/bin/env python3
#'description': "This module captures findings for reports in regions that support AWS Inspector. The optional argument --download-reports will automatically download any reports found into the session downloads directory under a folder named after the run id of the inspector report.",
import datetime
import argparse
from botocore.exceptions import ClientError
import os
import urllib.request

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()
    
    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    regions = get_regions('Inspector')
    complete_data = {}
    summary_data = {
        'reports': 0,
        'findings': 0,
        'regions': regions,
    }
    if args.download_reports:
        summary_data['reports_location'] = 'sessions/{}/downloads/inspector_assessments/'.format(session.name)
    for region in regions:
        print('Starting region {}...'.format(region))

        client = awsattack_main.get_boto3_client('inspector', region)

        if args.download_reports:
            assessment_runs = []
            response = ''
            try:
                response = client.list_assessment_runs()
                assessment_runs += response['assessmentRunArns']
                while 'nextToken' in response:
                    response = client.list_findings(nextToken=response['nextToken'])
                    assessment_runs += response['assessmentRunArns']
            except ClientError as error:
                    if error.response['Error']['Code'] == 'AccessDeniedException':
                        print('Access Denied for list-assessment-runs')
            if not assessment_runs:
                print('  No assessment runs found for {}'.format(region))
            else:
                summary_data['reports'] += len(assessment_runs)
            for run in assessment_runs:
                response = client.get_assessment_report(
                    assessmentRunArn=run,
                    reportFileFormat='HTML',
                    reportType='FULL'
                )
                if response.get('url'):
                    if not os.path.exists('sessions/{}/downloads/inspector_assessments/'.format(session.name)):
                        os.makedirs('sessions/{}/downloads/inspector_assessments/'.format(session.name))
                    file_name = 'sessions/{}/downloads/inspector_assessments/'.format(session.name) + str(run)[-10:] + '.html'
                    print('  Report saved to: ' + file_name)
                    with urllib.request.urlopen(response['url']) as response, open(file_name, 'a') as out_file:
                        out_file.write(str(response.read()))
                else:
                    print('Failed to generate report for {} ({})...'.format(run, response['status']))
        findings = []
        try:
            response = client.list_findings()
            findings = response['findingArns']
            while 'nextToken' in response:
                response = client.list_findings(nextToken=response['nextToken'])
                findings += response['findingArns']
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('Access Denied for list-findings')
                continue
        try:
            if len(findings) < 1:
                print('  No findings found')
                continue
            else:
                print('  {} findings found'.format(len(findings)))
                summary_data['findings'] += len(findings)
            descriptions = client.describe_findings(findingArns=findings)['findings']
            complete_data[region] = descriptions
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('Access Denied for describe-findings')
    session.update(awsattack_main.database, Inspector=complete_data)
    return summary_data

