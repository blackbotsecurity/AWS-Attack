#!/usr/bin/env python3
import datetime

import argparse
import requests
import zipfile
import os
import re

from core.secretfinder.utils import regex_checker, contains_secret, Color
from botocore.exceptions import ClientError

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
            if args.versions_all:
                func['Versions'] = fetch_lambda_data(client, 'list_versions_by_function', 'Versions', print, FunctionName=func_arn)

            # Check for secrets in data
            check_evn_secrets(func)
            if args.checksource:
                check_source_secrets(session.name, func)
            
        lambda_data['Functions'] += lambda_functions
        if lambda_functions:
            summary_data[region] = len(lambda_functions)
    session.update(awsattack_main.database, Lambda=lambda_data)
   
    return summary_data


def summary(data, awsattack_main):
    out = ''
    for region in sorted(data):
        out += '  {} functions found in {}. View more information in the DB \n'.format(data[region], region)
    if not out:
        out = '  Nothing was enumerated'
    return out


def check_evn_secrets(function):
    try:
        env_vars = function['Environment']['Variables']
        [Color.print(Color.GREEN, '\t[+] Secret (ENV): {}= {}'.format(key, env_vars[key])) for key in env_vars if contains_secret(env_vars[key])]
    except KeyError:
        return

def check_source_secrets(session_name, function):
    pattern = "(#.*|//.*|\\\".*\\\"|'.*'|/\\*.*|\".*\")"

    source_data = get_function_source(session_name, function)

    for key in source_data:
        for line in re.findall(pattern, source_data[key]):
            secrets = regex_checker(line)
            if secrets:
                [Color.print(Color.GREEN, "\t{}: {}".format(key, secrets[key])) for key in secrets]
  

def get_function_source(session_name, func):
    try:
        # Get Link and setup file name
        fname = func['FunctionArn'].split(':')
        fname = fname[len(fname)-1]

        code_url = func['Code']['Location']

        # Download File from URL
        r = requests.get(code_url, stream=True)

        # Write Zip to output file
        fname = os.path.join('sessions/{}/downloads'.format(session_name), 'lambda_{}.zip'.format(fname))
        zfile = open(fname, 'wb')
        zfile.write(r.content)
        zfile.close()

        # Load Zip contents into memory
        lambda_zip = zipfile.ZipFile(fname)

        return {id: lambda_zip.read(name).decode("utf-8", errors='ignore') for name in lambda_zip.namelist()}

    except KeyError:
        print(Color.RED, 'Error getting {fname} Source'.format(fname))

