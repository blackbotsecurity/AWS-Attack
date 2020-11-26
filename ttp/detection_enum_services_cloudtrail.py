#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
from botocore.exceptions import ClientError,EndpointConnectionError

import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1526',
    'external_id': '',
    'controller': 'detection_enum_services_cloudtrail',
    'services': ['CloudTrail'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': [],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Detects monitoring and logging capabilities.',
    'name': 'ADD_NAME_HERE' ,

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

def main(args, awsattack_main, data=None):
    args = parser.parse_args(args)

    import_path = 'ttp.src.detection_enum_services_cloudtrail_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = ''
    if 'ShieldSubscription' in data:
        out += '  Shield Subscription Status: {}\n'.format(data['ShieldSubscription'])
        if data['ShieldSubscription'] == 'Active':
            out += '    Shield Subscription Start: {}\n'.format(data['ShieldSubscriptionStart'])
            out += '    Shield Subscription Length: {} day(s(\n'.format(data['ShieldSubscriptionLength'])
    if 'CloudTrails' in data:
        out += '  {} CloudTrail Trail(s) found.\n'.format(data['CloudTrails'])
    if 'Detectors' in data:
        out += '  {} GuardDuty Detector(s) found.\n'.format(data['Detectors'])
    if 'MasterDetectors' in data:
        out += '  {} Master GuardDuty Detector(s) found.\n'.format(data['MasterDetectors'])
    if 'config' in data:
        out += '  AWS Config Data:\n'
        out += '    {} Rule(s) found.\n'.format(data['config']['rules'])
        out += '    {} Recorder(s) found.\n'.format(data['config']['recorders'])
        out += '    {} Delivery Channel(s) found.\n'.format(data['config']['delivery_channels'])
        out += '    {} Aggregator(s) found.\n'.format(data['config']['aggregators'])
    if 'alarms' in data:
        out += '  {} CloudWatch Alarm(s) found.\n'.format(data['alarms'])
    if 'flowlogs' in data:
        out += '  {} VPC flow log(s) found.\n'.format(data['flowlogs'])

    if not out:
        return '  No data could be found'
    return out


def get_detector_master(detector_id, client):
    try:
        response = client.get_master_account(
            DetectorId=detector_id
        )
    except ClientError:
        raise
    if 'Master' not in response:
        return(None, None)

    status = None
    master = None

    if 'RelationshipStatus' in response['Master']:
        status = response['Master']['RelationshipStatus']

    if 'AccountId' in response['Master']:
        master = response['Master']['AccountId']

    return(status, master)
