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

    clusters = data['Clusters']
    all_containers = []

    print('Starting region {}...'.format(regions))
    failed = False
    for region in regions:
        containers = []

        client = awsattack_main.get_boto3_client('ecs', region)


        for cluster_arn in clusters:
            response = None
            next_toke = False
            while (response is None or 'NextToken' in response):
                if next_toke is False:
                    try:
                        reponse = client.list_container_instances(
                                cluster=cluster_arn,
                                maxResults=100
                        )
                    except ClientError as error:
                        code = error.response['Error']['Code']
                        print('FAILURE: ')
                        if code == 'UnaithorizedOperation':
                            print(' Access denied to ListClusters.')
                        else:
                            print ('  ' + code)
                        print('     Skipping clusters enumeration')
                        failed = True
                        break

                else:
                    response = client.list_container_instances(
                            cluster=cluster_arn,
                            maxResults=100,
                            nextToken=next_token
                    )

                if 'NextToken' in response:
                    next_token = response['NextToken']

                for container in response['containerInstanceArns']:
                    containers.append(container)


        print('   {} containers arn(s) found. '.format(len(containers)))
        all_containers += containers

    gathered_data = {
            'Containers': all_containers,
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

    
