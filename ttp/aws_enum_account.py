#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1087.004',
    'external_id': '',
    'controller': 'aws_enum_account',
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'services': ['IAM'],
    'prerequisite_modules': [],  
    'arguments_to_autocomplete': [],
    'version': '1',
    'aws_namespaces': [],
    'intent': 'Enumerates data About the account itself.',
    'name': 'Account Discovery: Cloud Account' ,
}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

# Main is the first function that is called when this module is executed
def main(args, awsattack_main, data=None):
    args = parser.parse_args(args)

    import_path = 'ttp.src.aws_enum_account_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = "Account Information:\n"
    out += "    Account ID: {}\n".format(data['account_id'])
    out += "    Account IAM Alias: {}\n".format(data['account_iam_alias'])
    out += "    Key Arn: {}\n".format(data['key_arn'])
    out += "    Account Spend: {} (USD)\n".format(data['account_total_spend'])
    if data.get('org_data', None) is not None:
        out += "    Parent Account:\n"
        for key in data['org_data'].keys():
            out += "        {}: {}\n".format(key, data['org_data'][key])
    return out
