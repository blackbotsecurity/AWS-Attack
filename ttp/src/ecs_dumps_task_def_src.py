#!/usr/bin/env python3
import datetime

from botocore.exceptions import ClientError


import argparse
import os
import json

def main(args, awsattack_main, data=None):
    session = session = awsattack_main.get_active_session()

    task_definitions = data
    summary_data = {"task_definitions": 0}

    if not os.path.exists('sessions/{}/downloads/ecs_task_def_data/'.format(session.name)):
        os.makedirs('sessions/{}/downloads/ecs_task_def_data/'.format(session.name))

    if task_definitions:
        print("Targeting {} task definition(s)...".format(len(task_definitions)))

        for task_def in task_definitions:
            region = task_def.split(':')[3]
            client = awsattack_main.get_boto3_client('ecs', region)

            try:
                task_def_data = client.describe_task_definition(
                    taskDefinition=task_def,
                )
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'AccessDenied':
                    print('  Access denied to DescribeTaskDefinition.')
                    print('Skipping the rest of the task definitions...')
                    break
                else:
                    print('  ' + code)
            
            formatted_data = "{}@{}\n{}\n\n".format(
                task_def,
                region,
                json.dumps(task_def_data['taskDefinition'], indent=4)
            )
           
            with open('sessions/{}/downloads/ecs_task_def_data/all_task_def.txt'.format(session.name), 'a+') as data_file:
                data_file.write(formatted_data)
            with open('sessions/{}/downloads/ecs_task_def_data/{}.txt'.format(session.name, task_def.split('/')[1].split(':')[0]), 'w+') as data_file:
                data_file.write(formatted_data.replace('\\t', '\t').replace('\\n', '\n').rstrip())
            summary_data['task_definitions'] += 1

    return summary_data

def summary(data, awsattack_main):
    session = awsattack_main.get_active_session()

    output = '  ECS Task Definition Data for {} task definition(s) was written to ./sessions/{}/downloads/ecs_task_def_data/'.format(data['task_definitions'],session.name)
    return output
