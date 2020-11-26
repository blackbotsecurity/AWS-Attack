#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
import os
import importlib

# When writing a module, feel free to remove any comments, placeholders, or
# anything else that doesn't relate to your module.

target = ''

technique_info = {
    'blackbot_id': 'T1552.b.007', # credential in services
    'external_id': '',
    'controller': 'enum_secrets_manager',
    'services': ['SecretsManager'],
    'prerequisite_modules': [],
    'external_dependencies': [],
    'arguments_to_autocomplete': ['--regions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Enumerates and dumps secrets from AWS Secrets Manager and AWS parameter store',
    'name': 'ADD_NAME_HERE',
}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])
parser.add_argument('--regions', required=False, help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all session regions.')

def main(args, awsattack_main):
    args = parser.parse_args(args)

    import_path = 'ttp.src.enum_secrets_manager_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main)



# The summary function will be called by AWSc2 after running main, and will be
# passed the data returned from main. It should return a single string
# containing a curated summary of every significant thing that the module did,
# whether successful or not; or None if the module exited early and made no
# changes that warrant a summary being displayed. The data parameter can
# contain whatever data is needed in any structure desired. A length limit of
# 1000 characters is enforced on strings returned by module summary functions.
def summary(data, awsattack_main):
    output = "    {} Secret(s) were found in AWS secretsmanager".format(data["SecretsManager"])
    output += "    \n    Check ./sessions/<session name>/downloads/secrets/ to get the values"
    return output
