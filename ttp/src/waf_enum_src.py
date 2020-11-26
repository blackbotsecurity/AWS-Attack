#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy

METHODS = [
    ('byte_match_sets', 'ByteMatchSets'),
    ('geo_match_sets', 'GeoMatchSets'),
    ('ip_sets', 'IPSets'),
    ('rate_based_rules', 'Rules'),
    ('regex_match_sets', 'RegexMatchSets'),
    ('regex_pattern_sets', 'RegexPatternSets'),
    ('rule_groups', 'RuleGroups'),
    ('rules', 'Rules'),
    ('size_constraint_sets', 'SizeConstraintSets'),
    ('sql_injection_match_sets', 'SqlInjectionMatchSets'),
    ('subscribed_rule_groups', 'RuleGroups'),
    ('web_acls', 'WebACLs'),
    ('xss_match_sets', 'XssMatchSets'),
]


def grab_data(client, function, key, **kwargs):
    """Grabs all data given a function and a key."""
    out = []
    caller = getattr(client, function)
    try:
        response = caller(**kwargs)
        out.extend(response[key])
        while 'NextMarker' in response:
            response = caller(**kwargs, NextMarker=response['NextMarker'])
            out.extend(response[key])
        print('   Found {} {}'.format(len(out), key))
    except ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            print('AccessDenied for: {}'.format(function))
        return []
    return out


def grab_id_data(client, func, param):
    """Helper function to grab conditions and filters for WAF resources."""
    caller = getattr(client, func)
    try:
        response = caller(**param)
        del response['ResponseMetadata']
        # Pull out the actual fields from the response and return them.
        for key in response:
            return response[key]
    except ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            print('AccessDenied for: {}'.format(func))
    return {}


def consistentCase(description):
    """Converts snake_case strings to CameCase"""
    splitted = description.split('_')
    out = ''.join([word[0].upper() + word[1:] for word in splitted])
    return out


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()
    
    print = awsattack_main.print
    get_regions = awsattack_main.get_regions
    regions = get_regions('waf-regional') if args.regions is None else args.regions.split(',')

    waf_regional_data = {}
    waf_global_data = {}
    for key, val in METHODS:
        waf_regional_data[val] = []
        waf_global_data[val] = []

    for region in regions:
        print('  Staring enumeration of region: {}...'.format(region))
        client = awsattack_main.get_boto3_client('waf-regional', region)
        for func, key in METHODS:
            items = grab_data(client, 'list_' + func, key)
            for index, item in enumerate(items):
                param_key = key[:-1] + 'Id'
                param = {param_key: item[param_key]}
                new_data = grab_id_data(client, 'get_' + func[:-1], param)
                new_data['region'] = region
                items[index] = new_data
            waf_regional_data[key].extend(items)

    # Grab additional data specifically for RuleGroups.
    for rule_group in waf_regional_data['RuleGroups']:
        region = rule_group['region']
        client = awsattack_main.get_boto3_client('waf-regional', region)
        group_id = rule_group['RuleGroupId']
        rule_group['ActivatedRules'] = grab_data(
            client,
            'list_activated_rules_in_rule_group',
            'ActivatedRules',
            RuleGroupId=group_id
        )
    waf_region_data = deepcopy(session.WAFRegional)
    waf_region_data.update(waf_regional_data)
    session.update(awsattack_main.database, WAFRegional=waf_region_data)

    if args.global_region:
        client = awsattack_main.get_boto3_client('waf')
        print('  Starting enumeration for global WAF...')
        for func, key in METHODS:
            items = grab_data(client, 'list_' + func, key)
            for index, item in enumerate(items):
                param_key = key[:-1] + 'Id'
                param = {param_key: item[param_key]}
                new_data = grab_id_data(client, 'get_' + func[:-1], param)
                items[index] = new_data
            waf_global_data[key].extend(items)

        # Grab additional data specifically for RuleGroups.
        for rule_group in waf_global_data['RuleGroups']:
            group_id = rule_group['RuleGroupId']
            rule_group['ActivatedRules'] = grab_data(
                client,
                'list_activated_rules_in_rule_group',
                'ActivatedRules',
                RuleGroupId=group_id
            )
        waf_data = deepcopy(session.WAF)
        waf_data.update(waf_global_data)
        session.update(awsattack_main.database, WAF=waf_data)

    summary_data = {}
    for func, key in METHODS:
        summary_data[key] = len(waf_global_data[key]) + len(waf_regional_data[key])
    return summary_data


def summary(data, awsattack_main):
    out = ''
    for key in data:
        out += '  Found {} Total {}.\n'.format(data[key], key)
    return out
