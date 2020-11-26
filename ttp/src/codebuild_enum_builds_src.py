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

    all_builds = []
    summary_data = {}
    for region in regions:
        region_builds = []
        summary_data[region] = {}

        print('Startin region {}...'.format(region))
        client = awsattack_main.get_boto3_client('codebuild', region)

        # Builds
        build_ids = []
        response = {}
        try:
            response = client.list_builds()
            build_ids.extend(response['ids'])
        except ClientError as error:
           if error.response['Error']['Code'] == 'AccessDeniedException':
               print('No code-builds builds got for region: {} - AccessDeniedException'.format(region))
               print('ClientError getting builds: {}'.format(error))

           
        while 'nextToken' in response:
            response = {}
            try:
                response = client.list_builds(
                    nextToken=response['nextToken']
                )
                build_ids.extend(response['ids'])
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDeniedException':
                    print('No further code-builds builds for region: {} - AccessDeniedException'.format(region))
                    print('ClientError getting further builds: {}'.format(error))

        if len(build_ids) > 0:
            region_builds = {}
            try:
                region_builds = client.batch_get_builds(
                    ids=build_ids
                )['builds']
                print('  Found {} builds'.format(len(region_builds)))
                summary_data[region]['Found'] = len(region_builds)
                summary_data[region]['Builds'] = region_builds
                all_builds.extend(region_builds)
            except ClientError as error:
                if error.response['Error']['Code'] == 'AccessDeniedException':
                    print('No info retrieved about code-builds for region: {} - AccessDeniedException'.format(region))
                    print('ClientError getting info about builds: {}'.format(error))

        if not summary_data[region]:
            del summary_data[region]

    return summary_data
