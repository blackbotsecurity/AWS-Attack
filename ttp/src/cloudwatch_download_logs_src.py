#!/usr/bin/env python3
import datetime

import argparse
import csv
import datetime
import os

import pytz
from botocore.exceptions import ClientError

def write_stream_file(session_name, scan_time, group_name, stream_name, events):
    if not events:
        return True
    stream_group_path = os.path.join(
        os.getcwd(), 'sessions', session_name, 'downloads', 'cloud_watch_logs',
        str(scan_time), group_name[1:])
    if not os.path.exists(stream_group_path):
        os.makedirs(stream_group_path)
    file_name = os.path.join(
        stream_group_path, stream_name.replace('/', '_') + '.csv')
    flag = 'a' if os.path.isfile(file_name) else 'w'

    with open(file_name, flag, newline='') as out_file:
        event_writer = csv.writer(
            out_file,
            delimiter=',',
        )
        if flag == 'w':
            event_writer.writerow(['timestamp', 'message'])
        for event in events:
            event_writer.writerow([event['timestamp'], event['message']])
    return True


def collect_all(client, func, key, **kwargs):
    """Collects data and stores it in a list."""
    caller = getattr(client, func)
    try:
        response = caller(**kwargs)
        out = response[key]
        while 'nextToken' in response:
            response = caller({'nextToken': response['nextToken'], **kwargs})
            out += response[key]
        return out
    except ClientError as error:
        if error.response['Error']['Code'] == 'AccessDeniedException':
            print('AccessDenied for: {}'.format(func))
    return []


def millisecond(time_stamp):
    """Returns millisecond from timestamp"""
    return int(time_stamp.timestamp() * 1000 + time_stamp.microsecond / 1000)

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()
    
    print = awsattack_main.print
    get_regions = awsattack_main.get_regions
    summary_data = {}
    
    from_time = args[0]
    to_time = args[1]
    scan_time = args[2]

    regions = get_regions('logs')
    log_groups = {}

    for region in regions:
        print('Enumerating {}...'.format(region))
        client = awsattack_main.get_boto3_client('logs', region)
       
        groups = collect_all(client, 'describe_log_groups', 'logGroups')
        if not groups:
            print('  No Log Groups found')
            continue
        else:
            print('  {} Log Groups found'.format(len(groups)))
        group_names = [group['logGroupName'] for group in groups]
        for group in group_names:
            log_groups[group] = {}

        for log_group in log_groups:
            streams = collect_all(
                client, 'describe_log_streams', 'logStreams',
                **{'logGroupName': log_group})
            log_groups[log_group] = [stream['logStreamName'] for stream in streams]
        if not streams:
            print(' No Streams found')
            continue
        else:
            stream_count = sum([len(log_groups[key]) for key in log_groups])
            print('  {} Streams found'.format(stream_count))
        event_count = 0
        for group in log_groups:
            for stream in log_groups[group]:
                start_time = millisecond(from_time)
                end_time = millisecond(to_time) if to_time else None
                kwargs = {
                    'logGroupName': group,
                    'logStreamNames': [stream],
                    'startTime': start_time,
                }
                if end_time:
                    kwargs['endTime'] = end_time

                paginator = client.get_paginator('filter_log_events')
                page_iterator = paginator.paginate(**kwargs)

                # 2. Starts collection from the events discovered
                technique_info['tactic_id'].append('TA0009')
                technique_info['ttp_in'].append('T1530')
                for response in page_iterator:
                    event_count += len(response['events'])
                    write_stream_file(
                        session.name, scan_time, group, stream,
                        response['events'])
                print('    Captured Events for {}'.format(stream))
        summary_data[region] = {
            'groups': len(log_groups),
            'streams': sum([len(log_groups[key]) for key in log_groups]),
            'events': event_count,
        }
    dl_root = 'sessions/' + session.name + '/downloads/cloud_watch_logs/'
    summary_data['log_download_path'] = '{}{}'.format(dl_root, scan_time)

    return summary_data

