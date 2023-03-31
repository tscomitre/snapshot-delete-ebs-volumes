import os
import json
import boto3
import logging

from datetime import date, datetime
from random import randrange
from botocore.exceptions import ClientError

# Setup logger
logger = logging.getLogger()
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO').upper())

# Variables
volumes_table_name = 'ebs-automation-volumes'


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f'Type {type(obj)} not serializable')


def create_client(service):
    """
    Creates a service client
    :param service: (string) AWS service which the client will be created for
    :return: client object
    """
    return boto3.client(service)


def assume_role(role_arn):
    """
    Assume a Cross Account IAM Role
    :param role_arn: (string) Cross Account IAM Role ARN
    :return: Credentials from created session
    """
    # Try to assume a Cross Account IAM Role
    try:
        # Create client
        client = create_client('sts')

        # Assume Cross Account IAM Role
        response = client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f'AssumeRoleSession-{randrange(10)}'
        )

        # Return the temporary credentials from the response
        return response['Credentials']

    # Log an exception if something goes wrong
    except Exception as ex:
        logger.error('An error has occurred while trying to assume a Cross Account IAM Role.')
        logger.error(ex)
        return False


def create_session(credentials, region_name=None):
    """
    Creates a Session with boto3
    :param credentials (dict) STS temporary credentials from AssumeRole
    :param region_name: (string) Default region when creating new connections
    :return: Session
    """
    if not region_name:
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )

    else:
        return boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
            region_name=region_name
        )


def describe_volumes(ebs_volume):
    """
    Describe a given EBS Volume
    :param ebs_volume: (dict)
                AccountId (str)
                VolumeId (str)
    :return: EBS Volume details
    """
    # Try to retrieve EBS Volume details
    logger.info(f"Retrieving details for EBS Volume [{ebs_volume['VolumeId']}].")
    try:
        # Assume a Cross Account IAM Role
        credentials = assume_role(f"arn:aws:iam::{ebs_volume['AccountId']}:role/tabcorp-superadmin")
        if not credentials:
            return False

        # Create session
        session = create_session(credentials, region_name='ap-southeast-2')

        # Create client
        client = session.client('ec2')

        # Describe an EBS Volume
        return client.describe_volumes(
            VolumeIds=[ebs_volume['VolumeId']]
        )['Volumes'][0]

    # Log an exception if something goes wrong
    except ClientError as ex:
        logger.error('An error has occurred while trying to describe an EBS Volume.')
        logger.error(ex)
        return False
    except Exception as ex:
        logger.error('An error has occurred while trying to describe an EBS Volume.')
        logger.error(ex)
        return False


def create_resource(service, region=None):
    """
    Creates a service resource
    :param service: (string) AWS service which the resource will be created for
    :param region: (string) AWS region where the resource will be created for
    :return: resource object
    """
    if not region:
        return boto3.resource(service)

    else:
        return boto3.resource(service, region_name=region)


def get_item(table_name, **kwargs):
    """
    Get an item from DynamoDB Table
    :param table_name: (string) The name of the table containing the requested item
    :param kwargs:
                hash_key - (string) The Hash Key set for the table
                hash_value - (string) The Hash Key value of the item to retrieve
                range_key - (string) The Range Key set for the table
                range_value - (string) The Range Key value of the item to retrieve
    :return: A set of attributes for the item with the given primary key. If there is no matching item, it will not
             return any data and there will be no Item element in the response.
    """
    # Try to get an item from DynamoDB Table
    try:
        # Create resource Table
        table = create_resource('dynamodb', 'ap-southeast-2').Table(table_name)

        # Get item
        if 'range_key' not in kwargs:
            response = table.get_item(Key={kwargs['hash_key']: kwargs['hash_value']})

        else:
            response = table.get_item(
                Key={
                    kwargs['hash_key']: kwargs['hash_value'],
                    kwargs['range_key']: kwargs['range_value']
                }
            )

        if 'Item' not in response:
            return False

        else:
            return response['Item']

    # Log an exception if something goes wrong
    except Exception as ex:
        logger.error('An error has occurred while trying to get an item from DynamoDB Table.')
        logger.error(ex)
        return False


def put_item(table_name, item):
    """
    Creates a new item, or replaces an old item with a new item into DynamoDB Table
    :param table_name: (string) The name of the table to insert the item.
    :param item: (dict) The item
    :return: The output of a PutItem operation
    """
    # Try to put an item into DynamoDB Table
    try:
        # Create resource Table
        table = create_resource('dynamodb').Table(table_name)

        # Put item in the table
        return table.put_item(Item=item)

    # Log an exception if something goes wrong
    except Exception as ex:
        logger.error('An error has occurred while trying to put an item into DynamoDB Table.')
        logger.error(ex)
        return False


def main_handler(event, context):
    """
    Create Snapshot of an EBS Volume and Delete volume once completed
    :param event: (dict) AWS Lambda Function event
    :param context: (dict) AWS Lambda Function context
    """
    logger.debug(f'Lambda Event: {event}')
    logger.debug(f'Lambda Context: {context}')

    # Opening JSON file
    with open('load_volumes.json') as json_file:
        data = json.load(json_file)

        # Get EBS Volume details and put into DynamoDB Table
        for item in data:
            volume_details = describe_volumes(item)

            # Add EBS Volume details into DynamoDB Table
            if volume_details:
                print(volume_details)

                # Get client details from DynamoDB Table
                volume_ddb_item = get_item(volumes_table_name, hash_key='VolumeId',
                                           hash_value=volume_details['VolumeId'])

                if not volume_ddb_item:
                    logger.warning('EBS Volume does not exist in the DynamoDB.')
                    logger.info('Adding EBS Volume details into DynamoDB Table.')

                    volume_details_ = json.dumps(volume_details, default=json_serial)
                    payload = json.loads(volume_details_)
                    payload['AccountId'] = item['AccountId']

                    if not put_item(volumes_table_name, payload):
                        logger.warning('EBS Volume could not be added into DynamoDB Table.')
                    else:
                        logger.info('EBS Volume successfully added into DynamoDB Table.')

                else:
                    logger.info('EBS Volume details already exists in DynamoDB Table. Skipping!')

    # return {
    #     'statusCode': 200,
    #     'headers': {'Content-Type': 'application/json'},
    #     'body': {'message': f'AWS Accounts successfully listed.'}
    # }


main_handler('event', 'context')
