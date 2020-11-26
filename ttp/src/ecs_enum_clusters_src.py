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
            print('THis technique is not supported in any regions specified in the current sessions region set. Exiting...')
            return None
    else:
        regions = args.regions.split(',')

    all_clusters = []

    print('Starting region {}...'.format(regions))
    failed = False
    for region in regions:
        clusters = []

        client = awsattack_main.get_boto3_client('ecs', region)

        response = None
        while (response is None):
            try:
                client.list_clusters()
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
                response = client.list_clusters()

            for arn in response['clusterArns']:
                clusters.append(arn)
        print('   {} cluster arn(s) found. '.format(len(clusters)))
        all_clusters += clusters

    gathered_data = {
            'Clusters': all_clusters,
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

    
