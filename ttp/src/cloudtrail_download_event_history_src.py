#!/usr/bin/env python3
import datetime

import argparse
import json
import time


def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions
    
    summary_data = {}
    if args.regions is None:
        regions = get_regions('cloudtrail')
        if regions is None or regions == [] or regions == '' or regions == {}:
            print('This module is not supported in any regions specified in the current sessions region set. Exiting...')
            return
    else:
        regions = args.regions.split(',')
    
    for region in regions:
        events = []
        print('Downloading logs from {}:'.format(region))
        print(' This may take a while...')
        client = awsattack_main.get_boto3_client('cloudtrail', region)

        event_history = client.lookup_events(
            MaxResults=50,
        )
        events += event_history['Events']

        while 'NextToken' in event_history:
            print('  Processing additional results...')
            event_history = client.lookup_events(
                MaxResults=50,
                NextToken=event_history['NextToken']
            )
            events += event_history['Events']
            
        
        summary_data[region] = len(events)
        #print('Finished enumerating {}'.format(region))
        
        now = time.time()
        with open('sessions/{}/downloads/cloudtrail_{}_event_history_{}.json'.format(session.name, region, now), 'w+') as json_file:
            json.dump(events, json_file, indent=2, default=str)
        print('  Events written to ./sessions/{}/downloads/cloudtrail_{}_event_history_{}.json'.format(session.name, region, now))

    return summary_data
