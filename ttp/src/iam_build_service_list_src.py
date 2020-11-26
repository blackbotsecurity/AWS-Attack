#!/usr/bin/env python3
import datetime


# 'description': "This module will automatically run through all possible API calls of supported services in order to enumerate permissions without the use of the IAM API.",
import argparse
import json
import os
import re
import boto3
from botocore.exceptions import ClientError
from botocore.exceptions import ParamValidationError
from . import param_generator

SUPPORTED_SERVICES = [
    'ec2',
    's3',
    'logs'
]

current_client = None
current_region = None
current_service = None

summary_data = {}


def complete_service_list():
    """Returns a list of all supported boto3 services"""
    session = boto3.session.Session()
    return session.get_available_services()


def build_service_list(services=None):
    """Returns a list of valid services. """
    if not services:
        return SUPPORTED_SERVICES

    unsupported_services = [service for service in services if service not in SUPPORTED_SERVICES]
    summary_data['unsupported'] = unsupported_services

    unknown_services = [service for service in unsupported_services if service not in complete_service_list()]
    summary_data['unknown'] = unknown_services
    service_list = [service for service in services if service in SUPPORTED_SERVICES]
    return service_list

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()
    print = awsattack_main.print

    service_list = build_service_list(args.services.split(',')) if args.services else build_service_list()
    summary_data['services'] = service_list
    
    return summary_data

