#!/usr/bin/env python3
import datetime


#'description': "This module examines Lightsail data fields and automatically enumerates them for all available regions. Available fields can be passed upon execution to only look at certain types of data. By default, all Lightsail fields will be captured.",

import argparse
from botocore.exceptions import ClientError

def setup_storage(fields):
    out = {}
    for field in fields:
        out[field] = []
    return out

# Converts snake_case to camelcase.
def camelCase(name):
    splitted = name.split('_')
    out = splitted[0]
    for word in splitted[1:]:
        out += word[0].upper() + word[1:]
    return out


def fetch_lightsail_data(client, func, print):
    # Adding 'get_' portion to each field to build command.
    caller = getattr(client, 'get_' + func)
    try:
        response = caller()
        data = response[camelCase(func)]
        while 'nextPageToken' in response:
            response = caller(pageToken=response['nextPageToken'])
            data.extend(response[camelCase(func)])
        print('    Found {} {}'.format(len(data), func))
        if func != 'active_names':
            for resource in data:
                resource['region'] = client.meta.region_name
        return data
    except ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            print('  {}'.format(func))
            print('    FAILURE: MISSING REQUIRED AWS PERMISSIONS')
        else:
            print('Unknown Error:\n{}'.format(error))
    return []


def main(args, awsattack_main):
    fields = ['disk_snapshots']
    session = awsattack_main.get_active_session()
    
    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    lightsail_data = setup_storage(fields)
    regions = get_regions('lightsail')

    for region in regions:
        print('Starting region {}...'.format(region))
        client = awsattack_main.get_boto3_client('lightsail', region)
        for field in fields:
            lightsail_data[field].extend(fetch_lightsail_data(client, field, print))

    summary_data = {'regions': regions}
    for field in lightsail_data:
        summary_data[field] = len(lightsail_data[field])

    session.update(awsattack_main.database, Lightsail=lightsail_data)
    return summary_data

