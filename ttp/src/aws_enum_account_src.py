#!/usr/bin/env python3
import datetime
import argparse
from botocore.exceptions import ClientError

def main(args, awsattack_main):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print

    sts_client = awsattack_main.get_boto3_client('sts')
    response = sts_client.get_caller_identity()
    key_arn = response['Arn']
    account_id = response['Account']

    iam_client = awsattack_main.get_boto3_client('iam')
    try:
        response = iam_client.list_account_aliases()
        account_iam_alias = response['AccountAliases'][0]
    except (KeyError, IndexError):
        account_iam_alias = "<No IAM Alias defined>"
    except ClientError as e:
        print("ClientError has occurred when getting AccountAliases: {}".format(e))
        account_iam_alias = "<NotFound>"

    print('Enumerating Account: {}'.format(account_iam_alias))
    # All the billing seems to be in us-east-1. YMMV
    cwm_client = awsattack_main.get_boto3_client('cloudwatch', "us-east-1")
    try:
        response = cwm_client.get_metric_statistics(
            Namespace='AWS/Billing',
            MetricName='EstimatedCharges',
            Dimensions=[
                {
                    'Name': 'Currency',
                    'Value': 'USD'
                },
            ],
            StartTime=datetime.datetime.now() - datetime.timedelta(hours=6),
            EndTime=datetime.datetime.now(),
            Period=21600,  # 6 hours
            Statistics=['Maximum'],
            Unit='None'
        )
        if len(response['Datapoints']) == 0:
            account_spend = "unavailable"
        elif 'Maximum' not in response['Datapoints'][0]:
            account_spend = "unavailable"
        else:
            account_spend = response['Datapoints'][0]['Maximum']
    except ClientError as e:
        if e.response['Error']['Code'] == "AccessDenied":
            account_spend = "<unauthorized>"
        else:
            print("Unable to get Spend Data: {}".format(e))
            account_spend = "<ClientError>"

    try:
        org_client = awsattack_main.get_boto3_client('organizations')
        org_response = org_client.describe_organization()
        org_data = org_response['Organization']
    except ClientError as e:
        org_data = {}
        if e.response['Error']['Code'] == "AccessDeniedException":
            org_data['error'] = "Not Authorized to get Organization Data"
        else:
            print("Unable to get Organization Data: {}".format(e))
            org_data['error'] = "Error Getting Organization Data"

    account_data = {
        'account_id': account_id,
        'account_iam_alias': account_iam_alias,
        'account_total_spend': account_spend,
        'org_data': org_data
    }

    session.update(awsattack_main.database, Account=account_data)

    summary_data = {
        'key_arn': key_arn,
        **account_data
    }
    return summary_data

