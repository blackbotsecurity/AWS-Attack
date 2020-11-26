#!/usr/bin/env python3
#'description': "This module captures findings for reports in regions that support AWS Inspector. The optional argument --download-reports will automatically download any reports found into the session downloads directory under a folder named after the run id of the inspector report.",
import datetime
import argparse
from botocore.exceptions import ClientError
import os
import urllib.request

target = ''

technique_info = {
    'blackbot_id': 'T1537.b.001',
    'external_id': '',
    'controller': 'inspector_get_reports',
    'services': ['Inspector'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--download-reports'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Download Inspector vulnerabily Report via API',
    'name': 'Transfer Data to Cloud Account: Inspector Reports',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--download-reports', required=False, default=False, action='store_true', help='Optional argument to download HTML reports for each run')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.inspector_get_reports_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)


def summary(data, awsattack_main):
    out = '  Regions Enumerated:\n'
    for region in data['regions']:
        out += '    {}\n'.format(region)
    if 'reports_location' in data:
        out += '  Reports saved to: {}\n'.format(data['reports_location'])
    out += '  {} reports found.\n'.format(data['reports'])
    out += '  {} findings found.\n'.format(data['findings'])
    return out
