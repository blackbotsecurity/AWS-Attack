#!/usr/bin/env python3
import datetime

import argparse
from pathlib import Path

def main(args, awsattack_main, data=None):
    technique_info = data

    session = awsattack_main.get_active_session()
    print = awsattack_main.print
    get_regions = awsattack_main.get_regions
    summary_data = {'region_key_pairs': []}
    regions = get_regions('lightsail')

    dl_path = Path.cwd() / 'sessions' / session.name / 'downloads' / technique_info['name']
    if not dl_path.exists():
        dl_path.mkdir()
    summary_data['dl_path'] = str(dl_path.relative_to(Path.cwd() / 'sessions' / session.name))
    
    for region in regions:
        print('  Downloading default keys for {}...'.format(region))
        cur_path = dl_path / region
        if not cur_path.exists():
            cur_path.mkdir()
        client = awsattack_main.get_boto3_client('lightsail', region)
        downloaded_keys = client.download_default_key_pair()
        restructured_keys = {
            'publicKey': downloaded_keys['publicKeyBase64'],
            'privateKey': downloaded_keys['privateKeyBase64']
        }

        private_path = cur_path / 'default'
        with private_path.open('w', encoding='utf-8') as key_file:
            key_file.write(restructured_keys['privateKey'])
        public_path = cur_path / 'default.pub'
        with public_path.open('w', encoding='utf-8') as key_file:
            key_file.write(restructured_keys['publicKey'])

        summary_data['region_key_pairs'].append(region)
    return summary_data

