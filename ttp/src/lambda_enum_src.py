#!/usr/bin/env python3
import datetime

import argparse
import requests
import zipfile
import os
import re

from core.secretfinder.utils import regex_checker, contains_secret, Color
from botocore.exceptions import ClientError

SOURCE_ENTROPY_THRESHOLD = 3.8

def fetch_lambda_data(client, func, key, print, **kwargs):
    caller = getattr(client, func)
    try:
        response = caller(**kwargs)
        data = response[key]
        if isinstance(data, (dict, str)):
            return data
        while 'nextMarker' in response:
            response = caller({**kwargs, **{'NextMarker': response['nextMarker']}})
            data.extend(response[key])
        return data
    except client.exceptions.ResourceNotFoundException:
        pass
    except ClientError as error:
        print('  FAILURE:')
        code = error.response['Error']['Code']
        if code == 'AccessDeniedException':
            print('    MISSING NEEDED PERMISSIONS')
        else:
            print(code)
    return []


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    if args.regions:
        regions = args.regions.split(',')
    else:
        regions = get_regions('Lambda')

    lambda_data = {}
    summary_data = {}
    lambda_data['Functions'] = []
    summary_data['Functions'] = []
    for region in regions:
        print('Starting region {}...'.format(region))

        client = awsattack_main.get_boto3_client('lambda', region)

        try:
            account_settings = client.get_account_settings()
            # Delete any ResponseMetaData to have cleaner account_settings response
            del account_settings['ResponseMetadata']
            for key in account_settings:
                lambda_data[key] = account_settings[key]
        except ClientError as error:
            if error.response['Error']['Code'] == 'AccessDeniedException':
                print('Access Denied for get-account-settings')
            else:
                print(error)

        lambda_functions = fetch_lambda_data(client, 'list_functions', 'Functions', print)

        for func in lambda_functions:
            print('  Enumerating data for {}'.format(func['FunctionName']))
            func_arn = func['FunctionArn']
            func['Region'] = region
            func['Code'] = fetch_lambda_data(client, 'get_function', 'Code', print, FunctionName=func_arn)
            func['Aliases'] = fetch_lambda_data(client, 'list_aliases', 'Aliases', print, FunctionName=func_arn)
            func['EventSourceMappings'] = fetch_lambda_data(client, 'list_event_source_mappings', 'EventSourceMappings', print, FunctionName=func_arn)
            func['Tags'] = fetch_lambda_data(client, 'list_tags', 'Tags', print, Resource=func_arn)
            func['Policy'] = fetch_lambda_data(client, 'get_policy', 'Policy', print, FunctionName=func_arn)
            if args.version_all:
                func['Versions'] = fetch_lambda_data(client, 'list_versions_by_function', 'Versions', print, FunctionName=func_arn)

        lambda_data['Functions'] += lambda_functions
        summary_data['Functions'].append(lambda_functions)
        if lambda_functions:
            summary_data[region] = len(lambda_functions)

   
    return summary_data



