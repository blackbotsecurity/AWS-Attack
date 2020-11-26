#!/usr/bin/env python3
import datetime

import argparse
import requests
import zipfile
import os
import re

from core.secretfinder.utils import regex_checker, contains_secret, Color
from botocore.exceptions import ClientError


def main(args, awsattack_main, data=None):
    global summary_data

    session = awsattack_main.get_active_session()

    print = awsattack_main.print

    summary_data = {}
    print(data)
    for func in data['Functions']:
        if func != []:
            check_evn_secrets(func)
            check_source_secrets(session.name, func)
            
    return summary_data


def check_evn_secrets(function):
    try:
        env_vars = function['Environment']['Variables']
        [Color.print(Color.GREEN, '\t[+] Secret (ENV): {}= {}'.format(key, env_vars[key])) for key in env_vars if contains_secret(env_vars[key])]
        summary_data['SecretEnv'] = [(key, env_vars[key]) for key in env_vars if contains_secret(env_vars[key])]
    except KeyError:
        return

def check_source_secrets(session_name, function):
    pattern = "(#.*|//.*|\\\".*\\\"|'.*'|/\\*.*|\".*\")"

    source_data = get_function_source(session_name, function)
    summary_data['Secrets'] = []
    for key in source_data:
        for line in re.findall(pattern, source_data[key]):
            secrets = regex_checker(line)
            if secrets:
                [Color.print(Color.GREEN, "\t{}: {}".format(key, secrets[key])) for key in secrets]
                summary_data['Secrets'].append([(key, secrets[key]) for key in secrets])
  

