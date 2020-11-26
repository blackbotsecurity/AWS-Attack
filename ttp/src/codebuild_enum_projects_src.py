#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
from botocore.exceptions import ClientError


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    regions = args.regions.split(',') if args.regions else get_regions('CodeBuild')

    all_projects = []
    summary_data = {}
    for region in regions:
        region_projects = []
        summary_data[region] = {}

        print('Starting region {}...'.format(region))
        client = awsattack_main.get_boto3_client('codebuild', region)

        # Begin enumeration

        # Projects
        project_names = []
        response = {}
        try:
            response = client.list_projects()
            project_names.extend(response['projects'])
            while 'nextToken' in response:
                response = client.list_projects(
                    nextToken=response['nextToken']
                )
                project_names.extend(response['projects'])

            if len(project_names) > 0:
                region_projects = client.batch_get_projects(
                    names=project_names
                )['projects']
                print('Found {} projects'.format(len(region_projects)))
                summary_data[region]['Found'] = len(region_projects)
                summary_data[region]['Projects'] = region_projects
                all_projects.extend(region_projects)
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('No projects got for region: {} - AccessDeniedException'.format(region))
                print('ClientError getting projects: {}'.format(error))

        if not summary_data[region]:
            del summary_data[region]

    return summary_data
