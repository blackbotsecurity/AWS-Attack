#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import subprocess
import random
import string
import os


def main(args, awsattack_main, data=None):
    technique_info = data
    session = awsattack_main.get_active_session()

    print = awsattack_main.print

    created_lambda_functions = []
    created_cwe_rules = []

    if os.path.isfile('./modules/{}/created-lambda-functions.txt'.format(technique_info['name'])):
        with open('./modules/{}/created-lambda-functions.txt'.format(technique_info['name']), 'r') as f:
            created_lambda_functions = f.readlines()
    if os.path.isfile('./modules/{}/created-cloudwatch-events-rules.txt'.format(technique_info['name'])):
        with open('./modules/{}/created-cloudwatch-events-rules.txt'.format(technique_info['name']), 'r') as f:
            created_cwe_rules = f.readlines()

    if created_lambda_functions:
        delete_function_file = True
        for function in created_lambda_functions:
            name = function.rstrip()
            print('  Deleting function {}...'.format(name))
            client = awsattack_main.get_boto3_client('lambda', 'us-east-1')
            try:
                client.delete_function(
                    FunctionName=name
                )
            except ClientError as error:
                code = error.response['Error']['Code']
                if code == 'AccessDeniedException':
                    print('  FAILURE: MISSING NEEDED PERMISSIONS')
                else:
                    print(code)
                delete_function_file = False
                break
        if delete_function_file:
            try:
                os.remove('./modules/{}/created-lambda-functions.txt'.format(technique_info['name']))
            except Exception as error:
                print('  Failed to remove ./modules/{}/created-lambda-functions.txt'.format(technique_info['name']))
                print('    {}: {}'.format(type(error), error))

    if created_cwe_rules:
        delete_cwe_file = True
        for rule in created_cwe_rules:
            name = rule.rstrip()
            print('  Deleting rule {}...'.format(name))
            client = awsattack_main.get_boto3_client('events', 'us-east-1')
            try:
                client.remove_targets(
                    Rule=name,
                    Ids=['0']
                )
                client.delete_rule(
                    Name=name
                )
            except ClientError as error:
                code = error.response['Error']['Code']
                if code == 'AccessDeniedException':
                    print('  FAILURE: MISSING NEEDED PERMISSIONS')
                else:
                    print(code)
                delete_cwe_file = False
                break
        if delete_cwe_file:
            try:
                os.remove('./modules/{}/created-cloudwatch-events-rules.txt'.format(technique_info['name']))
            except Exception as error:
                print('  Failed to remove ./modules/{}/created-cloudwatch-events-rules.txt'.format(technique_info['name']))
                print('    {}: {}'.format(type(error), error))

    print('Completed cleanup mode.\n')
    return {'cleanup': True}
