#!/usr/bin/env python3
#'descrption': ''Display what services the account uses and how much is spent. Data is pulled from CloudWatch metrics and the AWS/Billing Namespace.',
import datetime
import argparse
from botocore.exceptions import ClientError
import importlib

target = ''

technique_info = {
    'controller': 'aws__enum_spend',
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'blackbot_id': 'T1526.b.003',
    'external_id': '',
    'version': '1',
    'aws_namespaces': [],
    'intent': 'Enumerates account spend by service via Cloudwatch namespaces.',
    'name': 'Cloud Service Discovery: Cloudwatch Namespaces', 
    'services': ['IAM'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])

# Main is the first function that is called when this module is executed
def main(args, awsattack_main, data=None):
    args = parser.parse_args(args)

    import_path = 'ttp.src.aws_enum_spend_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)

def summary(data, awsattack_main):
    out = "Account Spend:\n"
    for key in sorted(data.keys(), key=lambda x: data[x], reverse=True):
        out += "        {:<30}: {:>10.2f} (USD)\n".format(key, data[key])
    return out
