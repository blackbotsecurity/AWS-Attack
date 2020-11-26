#!/usr/bin/env python3
#'descrption': ''Display what services the account uses and how much is spent. Data is pulled from CloudWatch metrics and the AWS/Billing Namespace.',
import datetime
import argparse
from botocore.exceptions import ClientError

# Main is the first function that is called when this module is executed
def main(args, awsattack_main, data=None):
    session = awsattack_main.get_active_session()

    print = awsattack_main.print

    # All the billing seems to be in us-east-1. YMMV
    cwm_client = awsattack_main.get_boto3_client('cloudwatch', "us-east-1")

    services = []
    service_spend = {}

    try:
        response = cwm_client.list_metrics(
            Namespace='AWS/Billing',
            MetricName='EstimatedCharges'
        )
        metrics = response['Metrics']
        for m in metrics:
            for d in m['Dimensions']:
                if d['Name'] == "ServiceName":
                    services.append(d['Value'])
        if len(services) == 0:
            print('\nNo services found. Unable to determine account spend.\n')
            return
    except ClientError as e:
        print("ClientError getting spend: {}".format(e))
        return({"error": "<unauthorized>"})

    for s in services:
        try:
            print("Retrieving metrics for service {}...".format(s))
            response = cwm_client.get_metric_statistics(
                Namespace='AWS/Billing',
                MetricName='EstimatedCharges',
                Dimensions=[
                    {
                        'Name': 'ServiceName',
                        'Value': s
                    },
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
                service_spend[s] = 0
            else:
                service_spend[s] = response['Datapoints'][0]['Maximum']
        except KeyError as e:
            print("KeyError getting spend: {} -- Response: {}".format(e, response))
        except IndexError as e:
            print("IndexError getting spend: {} -- Response: {}".format(e, response))
        except ClientError as e:
            print("ClientError getting spend: {}".format(e))

    session.update(awsattack_main.database, AccountSpend=service_spend)

    return service_spend
