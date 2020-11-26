import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
from random import choice

def main(args, awsattack_main, data=None):
    print = awsattack_main.print
    session = awsattack_main.get_active_session()
    get_regions = awsattack_main.get_regions
    
    if args.regions is None:
        regions = get_regions('ecs')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This technique is not supported in any regions specified in the current sessions region set. Exiting...')
            return None
    else:
        regions = args.regions.split(',')

    all_task_defs = []

    print('Starting region {}...'.format(regions))
    failed = False
    for region in regions:
        task_defs = []

        client = awsattack_main.get_boto3_client('ecs', region)

        response = None
        next_token = False
        while (response is None or 'nextToken' in response):
            if next_token is False:
                try:
                    response = client.list_task_definitions(
                            maxResults=100
                        )
                except ClientError as error:
                    code = error.response['Error']['Code']
                    print('FAILURE: ')
                    if code == 'UnauthorizedOperation':
                        print('  Access denied to ListTaskDefinitions')
                    else:
                        print('  ' + code)
                    print('  Skipping instance enuration...')
                    failed = True
                    break
            else:
                reponse = client.list_task_definitions(
                        maxResults=100,
                        nextToken=next_token
                    )
            if 'nextToken' is response:
                next_token = response['nextToken']

            for task_def in response['taskDefinitionArns']:
                task_defs.append(task_def)

        print('  {} task definition(s) found.'.format(len(task_defs)))
        all_task_defs += task_defs

    gathered_data = {
            'TaskDefinitions': all_task_defs,
        }
    
    ecs_data = deepcopy(session.ECS)
    for key, value in gathered_data.items():
        ecs_data[key] = value

    session.update(awsattack_main.database, ECS=ecs_data)

    gathered_data['regions'] = regions

    if not failed:
        return gathered_data
    else:
        print('No data successfully enumerated.\n')
        return None

    
