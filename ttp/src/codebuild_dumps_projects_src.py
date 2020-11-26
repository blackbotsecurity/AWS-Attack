#!/usr/bin/env python3
import datetime

import argparse
from copy import deepcopy
from botocore.exceptions import ClientError

def main(args, awsattack_main, data=None):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    # Begin environment variable dump
    
    environment_variables = []
    projects_list = []
    # Projects
    summary_data = {}
    for region in data:
        all_projects = data[region]['Projects']
        projects_list.extend(all_projects)

        for project in all_projects:
            if 'environment' in project and 'environmentVariables' in project['environment']:
                environment_variables.extend(project['environment']['environmentVariables'])


    # Store in session
    codebuild_data = deepcopy(session.CodeBuild)
    codebuild_data['EnvironmentVariables'] = environment_variables
    summary_data['All'] = {'EnvironmentVariables': len(environment_variables)}

    if len(projects_list) > 0:
        codebuild_data['Projects'] = projects_list
        summary_data['All']['Projects'] = len(projects_list)

    # TODO: need to check the field CodeBuild in the database
    session.update(awsattack_main.database, CodeBuild=codebuild_data)

    return summary_data

