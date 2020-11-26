#!/usr/bin/env python3
#'description': ''This module automatically creates API keys for every available region. There is an included cleanup feature to remove old "AWSc2" keys that are referenced by name.',
import datetime
import argparse
from copy import deepcopy
from botocore.exceptions import ClientError

def cleanup(awsattack_main, regions):
    print = awsattack_main.print
    for region in regions:
        client = awsattack_main.get_boto3_client('apigateway', region)
        try:
            keys = client.get_api_keys()['items']
            if len(keys) < 1:
                print('  No keys were found in {}'.format(region))
            for key in keys:
                if key['name'] == 'AWSc2':
                    try:
                        client.delete_api_key(apiKey=key['id'])
                        print('  Key deletion successful for: {}'.format(region))
                    except ClientError as error:
                        if error.response['Error']['Code'] == 'AccessDeniedException':
                            print('    FAILURE: ')
                            print('      MISSING NEEDED PERMISSIONS')
                            return False
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('    FAILURE: ')
                print('      MISSING NEEDED PERMISSIONS')
                return False
    return True


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions
    regions = args.regions.split(',') if args.regions else get_regions('apigateway')

    summary_data = {}
    api_keys = {}
    
    if cleanup(awsattack_main, regions):
        print('  Old Keys Cleaned')
        summary_data['cleanup'] = True
    else:
        print('  Failed to Cleanup Keys')
        summary_data['cleanup'] = False
        

    return summary_data

