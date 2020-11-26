#!/usr/bin/env python3
import datetime

from botocore.exceptions import ClientError

import argparse
import os
import json
import importlib

target = ''

technique_info = {
    'blackbot_id': 'T1530',
    'external_id': '',
    'controller': 'ecs_dumps_task_def',
    'services': ['ECS'],
    'prerequisite_modules': ['ecs_enum_taskdef'],
    'arguments_to_autocomplete': ['--task_definitions'],
    'version': '1',
    'aws_namespaces': [],
    'last_updated_by': 'Blackbot, Inc. Sun Sep 20 04:13:33 UTC 2020' ,
    'ttp_exec': '',
    'ttp_mitigation': '',
    'ttp_detection': '',
    'intent': 'Parses task definitions from ECS tasks',
    'name': 'ADD_NAME_HERE',

}

parser = argparse.ArgumentParser(add_help=False, description=technique_info['name'])
parser.add_argument('--task_definitions',required=False,default=None,help='A comma separated list of ECS task defintion ARNs (arn:aws:ecs:us-east-1:273486424706:task-definition/first-run-task-definition:latest)')

def main(args, awsattack_main):
    session = session = awsattack_main.get_active_session()
    args = parser.parse_args(args)
    fetch_data = awsattack_main.fetch_data

    task_definitions = []

    if args.task_definitions is not None:
        for task_def in args.task_definitions.split(','):
            task_definitions.append({
                'Task Defintion ID': task_def
            })
    else:
        if fetch_data(['ECS', 'TaskDefinitions'], technique_info['prerequisite_modules'][0], '--taskdef') is False:
            print('Pre-req module not run successfully. Exiting...')
            return None
        task_definitions = session.ECS['TaskDefinitions']

    import_path = 'ttp.src.ecs_dumps_task_def_src'
    src_code = __import__(import_path, globals(), locals(), ['technique_info'], 0)
    importlib.reload(src_code)

    awsattack_main.chain = True
    return src_code.main(args, awsattack_main, data=task_definitions)

def summary(data, awsattack_main):
    session = awsattack_main.get_active_session()

    output = '  ECS Task Definition Data for {} task definition(s) was written to ./sessions/{}/downloads/ecs_task_def_data/'.format(data['task_definitions'],session.name)
    return output
