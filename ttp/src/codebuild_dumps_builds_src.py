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
    builds_list = []

    # Builds
    summary_data = {}
    for region in data:
        all_builds = data[region]['Builds']
        builds_list.extend(all_builds)

        for build in all_builds:
            if 'environment' in build and 'environmentVariables' in build['environment']:
                environment_variables.extend(build['environment']['environmentVariables'])


    # Store in session
    codebuild_data = deepcopy(session.CodeBuild)
    codebuild_data['EnvironmentVariables'] = environment_variables
    summary_data['All'] = {'EnvironmentVariables': len(environment_variables)}

    if len(builds_list) > 0:
        codebuild_data['Builds'] = builds_list
        summary_data['All']['Builds'] = len(builds_list)

    # TODO: need to check the field CodeBuild in the database
    session.update(awsattack_main.database, CodeBuild=codebuild_data)

    return summary_data

