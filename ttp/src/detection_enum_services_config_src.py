#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
from botocore.exceptions import ClientError,EndpointConnectionError

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    summary_data = {}
    print('Starting Config...')
    config_regions = get_regions('config')
    all_rules = []
    all_delivery_channels = []
    all_configuration_recorders = []
    all_configuration_aggregators = []
    permissions = {
        'rules': True,
        'delivery_channels': True,
        'recorders': True,
        'aggregators': True,
    }
    for region in config_regions:
        if not any([permissions[action] for action in permissions]):
            print('  No Valid Permissions Found')
            print('    Skipping subsequent enumerations for remaining regions...')
            break
        print('  Starting region {}...'.format(region))

        client = awsattack_main.get_boto3_client('config', region)
        if permissions['rules']:
            paginator = client.get_paginator('describe_config_rules')
            rules_pages = paginator.paginate()

            rules = []
            try:
                for page in rules_pages:
                    rules.extend(page['ConfigRules'])
                for rule in rules:
                    rule['Region'] = region
                print('    {} rule(s) found.'.format(len(rules)))
            except ClientError as error:
                code = error.response['Error']['Code']
                if code == 'AccessDeniedException':
                    print('    ACCESS DENIED: DescribeConfigRules')
                    print('      Skipping subsequent enumerations...')
                    permissions['rules'] = False
                else:
                    print('    {}'.format(code))

            all_rules.extend(rules)

        if permissions['delivery_channels']:
            delivery_channels = []
            try:
                delivery_channels = client.describe_delivery_channels()['DeliveryChannels']
                try:
                    delivery_channels_status = client.describe_delivery_channel_status()['DeliveryChannelsStatus']
                except ClientError as error:
                    code = error.response['Error']['Code']
                    if code == 'AccessDeniedException':
                        print('    ACCESS DENIED: DescribeDeliveryChannelStatus')
                    else:
                        print('    {}'.format(code))
                for channel in delivery_channels:
                    channel['Region'] = region
                    for status in delivery_channels_status:
                        if channel['name'] == status['name']:
                            channel.update(status)  # Merge the channel "status" fields into the actual channel for the DB
                            break
                print('    {} delivery channel(s) found.'.format(len(delivery_channels)))
                all_delivery_channels.extend(delivery_channels)
            except ClientError as error:
                code = error.response['Error']['Code']
                if code == 'AccessDeniedException':
                    print('    ACCESS DENIED: DescribeDeliveryChannels')
                    print('      Skipping subsequent enumerations...')
                    permissions['delivery_channels'] = False
                else:
                    print('    {}'.format(code))

        if permissions['recorders']:
            configuration_recorders = []
            try:
                configuration_recorders = client.describe_configuration_recorders()['ConfigurationRecorders']
                try:
                    configuration_recorders_status = client.describe_configuration_recorder_status()['ConfigurationRecordersStatus']
                except ClientError as error:
                    code = error.response['Error']['Code']
                    if code == 'AccessDeniedException':
                        print('    ACCESS DENIED: DescribeConfigurationRecorderStatus')
                    else:
                        print('    {}'.format(code))
                for recorder in configuration_recorders:
                    recorder['Region'] = region
                    for status in configuration_recorders_status:
                        if recorder['name'] == status['name']:
                            recorder.update(status)  # Merge the recorder "status" fields into the actual recorder for the DB
                            break
                print('    {} configuration recorder(s) found.'.format(len(configuration_recorders)))
                all_configuration_recorders.extend(configuration_recorders)
            except ClientError as error:
                code = error.response['Error']['Code']
                if code == 'AccessDeniedException':
                    print('    ACCESS DENIED: DescribeConfigurationRecorders')
                    print('      Skipping subsequent enumerations...')
                    permissions['recorders'] = False
                else:
                    print('    {}'.format(code))

        # The following regions lack support for configuration aggregators.
        BAD_AGGREGATION_REGIONS = ['eu-west-2', 'ca-central-1', 'eu-west-3', 'sa-east-1', 'ap-south-1', 'ap-northeast-2']
        if region in BAD_AGGREGATION_REGIONS:
            print('    Skipping unsupported aggregator region...')
            continue

        if permissions['aggregators']:
            configuration_aggregators = []
            kwargs = {}
            while True:
                try:
                    response = client.describe_configuration_aggregators(**kwargs)
                except ClientError as error:
                    code = error.response['Error']['Code']
                    if code == 'AccessDeniedException':
                        print('    ACCESS DENIED: DescribeConfigurationAggregators')
                        print('      Skipping subsequent enumerations...')
                        permissions['aggregators'] = False
                    else:
                        print('    {}'.format(code))
                    break
                configuration_aggregators = response['ConfigurationAggregators']
                if 'NextToken' in response:
                    kwargs['NextToken'] = response['NextToken']
                else:
                    for aggregator in configuration_aggregators:
                        aggregator['Region'] = region
                    print('    {} configuration aggregator(s) found.'.format(len(configuration_aggregators)))
                    all_configuration_aggregators.extend(configuration_aggregators)
                    break

    config_data = deepcopy(session.Config)
    config_data['Rules'] = all_rules
    config_data['Recorders'] = all_configuration_recorders
    config_data['DeliveryChannels'] = all_delivery_channels
    config_data['Aggregators'] = all_configuration_aggregators
    session.update(awsattack_main.database, Config=config_data)

    print('  {} total Config rule(s) found.'.format(len(session.Config['Rules'])))
    print('  {} total Config recorder(s) found.'.format(len(session.Config['Recorders'])))
    print('  {} total Config delivery channel(s) found.'.format(len(session.Config['DeliveryChannels'])))
    print('  {} total Config aggregator(s) found.\n'.format(len(session.Config['Aggregators'])))
    summary_data.update({
        'config': {
            'rules': len(all_rules),
            'recorders': len(all_configuration_recorders),
            'delivery_channels': len(all_delivery_channels),
            'aggregators': len(all_configuration_aggregators),
        }
    })


    return summary_data

