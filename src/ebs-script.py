import os
import json
import boto3
import logging

from datetime import date, datetime
from random import randrange
from botocore.exceptions import ClientError, WaiterError

# Setup logger
logger = logging.getLogger()
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO').upper())

# Variables
volumes_table_name = 'ebs-automation-volumes'
role_name = os.getenv('ROLE_NAME', 'OrganizationAccountAccessRole')
today = str(date.today())


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
        credentials = assume_role(f"arn:aws:iam::{ebs_volume['AccountId']}:role/{role_name}")
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


def create_resource(service):
    """
    Creates a service resource
    :param service: (string) AWS service which the resource will be created for
    :return: resource object
    """
    return boto3.resource(service)


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
        table = create_resource('dynamodb').Table(table_name)

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


def scan(table_name):
    """
    Scan a given DynamoDB Table
    :param table_name: (string) The name of the table to be scanned
    :return: A list of items and item attributes from a DynamoDB Table
    """
    # Try to scan a DynamoDB Table
    try:
        # Create resource Table
        table = create_resource('dynamodb').Table(table_name)

        # Scan the table
        response = table.scan()

        items = [item for item in response['Items']]

        while 'LastEvaluatedKey' in response:
            response = table.scan(
                ExclusiveStartKey=response['LastEvaluatedKey']
            )

            for item in response['Items']:
                items.append(item)

        return items

    # Log an exception if something goes wrong
    except Exception as ex:
        logger.error('An error has occurred while trying to scan a DynamoDB Table.')
        logger.error(ex)
        return False


def describe_snapshots(volume_id, account_id):
    """
    Describe the EBS snapshots available for the given EBS Volume ID
    :param volume_id: (string) The ID of the volume the snapshot is for
    :param account_id: (string) The ID of the account which the snapshot belongs to
    :return: A list of snapshot for a given EBS Volume ID
    """
    # Try to describe EBS Snapshots
    logger.info(f'Retrieving details for EBS Snapshots of Volume [{volume_id}].')
    try:
        # Assume a Cross Account IAM Role
        credentials = assume_role(f"arn:aws:iam::{account_id}:role/{role_name}")
        if not credentials:
            return False

        # Create session
        session = create_session(credentials, region_name='ap-southeast-2')

        # Create client
        client = session.client('ec2')

        # Describe EBS Snapshots of a given Volume ID
        response = client.describe_snapshots(
            Filters=[
                {
                    'Name': 'volume-id',
                    'Values': [volume_id]
                }
            ]
        )

        snapshots = [snap for snap in response['Snapshots']]

        while 'NextToken' in response:
            response = client.describe_snapshots(
                Filters=[
                    {
                        'Name': 'volume-id',
                        'Values': [volume_id]
                    }
                ],
                NextToken=response['NextToken']
            )

            for snap in response['Snapshots']:
                snapshots.append(snap)

        return snapshots

    # Log an exception if something goes wrong
    except Exception as ex:
        logger.error('An error has occurred while trying to describe an EBS Snapshots of a specified EBS Volume.')
        logger.error(ex)
        return False


def delete_snapshot(snapshot_id, account_id):
    """
    Deletes the specified EBS Snapshot
    :param snapshot_id: (string) The ID of the EBS snapshot to be deleted
    :param account_id: (string) The ID of the account which the snapshot belongs to
    :return: True if successful, otherwise False
    """
    # Try to delete a given EBS Snapshot
    logger.info(f'Deleting EBS Snapshot [{snapshot_id}].')
    try:
        # Assume a Cross Account IAM Role
        credentials = assume_role(f"arn:aws:iam::{account_id}:role/{role_name}")
        if not credentials:
            return False

        # Create session
        session = create_session(credentials, region_name='ap-southeast-2')

        # Create client
        client = session.client('ec2')

        # Delete EBS Snapshot
        client.delete_snapshot(
            SnapshotId=snapshot_id,
            DryRun=True
        )
        return True

    # Log an exception if something goes wrong
    except Exception as ex:
        logger.error('An error has occurred while trying to delete an EBS Snapshot.')
        logger.error(ex)
        return False


def create_snapshot(volume_id, account_id, description, tags):
    """
    Create a snapshot of an EBS volume and stores it in Amazon S3
    :param volume_id: (string) The ID of the Amazon EBS volume
    :param account_id: (string) The ID of the account which the volume belongs to
    :param description: (string) A description for the snapshot
    :param tags: (list) The tags to apply to the snapshot during creation
    :return: EBS Snapshot details
    """
    # Try to create an EBS Snapshot of a given EBS Volume
    logger.info(f'Creating snapshot of EBS Volume[{volume_id}].')
    try:
        # Assume a Cross Account IAM Role
        credentials = assume_role(f"arn:aws:iam::{account_id}:role/{role_name}")
        if not credentials:
            return False

        # Create session
        session = create_session(credentials, region_name='ap-southeast-2')

        # Create client
        client = session.client('ec2')

        # Delete EBS Snapshot
        return client.create_snapshot(
            Description=description,
            VolumeId=volume_id,
            TagSpecifications=[
                {
                    'ResourceType': 'snapshot',
                    'Tags': tags
                }
            ],
            DryRun=True
        )

    # Log an exception if something goes wrong
    except Exception as ex:
        logger.error('An error has occurred while trying to create an EBS Snapshot.')
        logger.error(ex)
        return False


def get_waiter(waiter_name, account_id, snapshot_id):
    """
    Wait for some condition
    :param waiter_name: (string) The name of the waiter to get
    :param account_id: (string) The ID of the account which the snapshot belongs to
    :param snapshot_id: (string) The ID of the snapshot
    :return: True if successful, otherwise False
    """
    # Try to get an EBS Snapshot waiter
    try:
        # Assume a Cross Account IAM Role
        credentials = assume_role(f"arn:aws:iam::{account_id}:role/{role_name}")
        if not credentials:
            return False

        # Create session
        session = create_session(credentials, region_name='ap-southeast-2')

        # Create client
        client = session.client('ec2')

        # Provide the contents of the request
        waiter = client.get_waiter(waiter_name)
        waiter.wait(SnapshotIds=[snapshot_id])
        return True

    # Log an exception if something goes wrong
    except WaiterError as ex:
        logger.error('Waiter encountered an unexpected state.')
        logger.error(ex)
        return False


def delete_volume(account_id, volume_id):
    """
    Delete the specified EBS volume
    :param account_id: (string) The ID of the account which the volume belongs to
    :param volume_id: (string) The ID of the volume to be deleted
    :return: True if successful, otherwise False
    """
    # Try to delete an EBS Volume
    try:
        # Assume a Cross Account IAM Role
        credentials = assume_role(f"arn:aws:iam::{account_id}:role/{role_name}")
        if not credentials:
            return False

        # Create session
        session = create_session(credentials, region_name='ap-southeast-2')

        # Create client
        client = session.client('ec2')

        # Provide the contents of the request
        return client.delete_volume(
            VolumeId=volume_id,
            DryRun=True
        )

    # Log an exception if something goes wrong
    except Exception as ex:
        logger.error('An error has occurred while trying to delete an EBS Volume.')
        logger.error(ex)
        return False


def main_handler():
    """
    Create Snapshot of an EBS Volume and Delete volume once completed
    """
    # Opening JSON file
    with open('load_volumes.json') as json_file:
        data = json.load(json_file)

        # Get EBS Volume details and put into DynamoDB Table
        for item in data:
            volume_details = describe_volumes(item)

            if not volume_details:
                logger.error(f"EBS Volume [{item['VolumeId']}] could not be described. Skipping!")
                continue

            # Check if EBS Volume is available/detached still
            if volume_details['State'] != 'available'
                logger.warning(f"EBS Volume [{item['VolumeId']}] is not available/detached anymore. Skipping!")
                continue

            # Add EBS Volume details into DynamoDB Table
            logger.info(f"EBS Volume [{item['VolumeId']}] successfully described.")
            logger.info(volume_details)

            # Get EBS Volume details from DynamoDB Table
            logger.info(f"Retrieving EBS Volume details from DynamoDB Table.")
            volume_ddb_item = get_item(volumes_table_name, hash_key='VolumeId', hash_value=volume_details['VolumeId'])

            if not volume_ddb_item:
                logger.warning('EBS Volume does not exist in the DynamoDB Table.')
                logger.info('Adding EBS Volume details into DynamoDB Table.')

                volume_details_ = json.dumps(volume_details, default=json_serial)
                payload = json.loads(volume_details_)
                payload['AccountId'] = item['AccountId']
                payload['date_checked'] = today

                if not put_item(volumes_table_name, payload):
                    logger.warning('EBS Volume could not be added into DynamoDB Table.')
                else:
                    logger.info('EBS Volume successfully added into DynamoDB Table.')

            else:
                logger.info('EBS Volume details already exists in DynamoDB Table. Skipping!')

    # Check Available EBS Volumes from DynamoDB
    available_volumes_list = scan(volumes_table_name)

    for volume in available_volumes_list:
        # List current snapshots for the volume
        snapshot_list = describe_snapshots(volume['VolumeId'], volume['AccountId'])

        if not snapshot_list:
            logger.error(f"EBS Snapshots of Volume [{volume['VolumeId']}] could not be described. Skipping!")
            continue

        # Delete current EBS Snapshots
        for snapshot in snapshot_list:
            if not delete_snapshot(snapshot['SnapshotId'], snapshot['OwnerId']):
                logger.error(f"EBS Snapshot [{snapshot['SnapshotId']}] could not be deleted. Skipping!")
                continue

            else:
                logger.info(f"EBS Snapshot [{snapshot['SnapshotId']}] successfully deleted.")\

        # Create a final snapshot of the EBS Volume that will be deleted
        logger.info(f"Creating a Final Snapshot of EBS Volume [{volume['VolumeId']}].")
        description = 'Final Snapshot as per Cost Optimisation Program'
        tags = volume['Tags']
        tags.append({'Key': 'CreatedBy', 'Value': 'Cloud Team'})
        tags.append({'Key': 'CreatedOn', 'Value': today})

        response_snap = create_snapshot(volume['VolumeId'], volume['AccountId'], description, tags)
        if not response_snap:
            logger.error(f"Final Snapshot of EBS Volume [{volume['VolumeId']}] could not be created. Skipping!")
            continue

        else:
            # Wait for snapshot to be completed
            if not get_waiter('snapshot_completed', volume['AccountId'], response_snap['SnapshotId']):
                logger.error(f"EBS Snapshot [{response_snap['SnapshotId']}] could not be completed. Skipping!")
                continue

            else:
                logger.info(f"Final Snapshot of EBS Volume [{volume['VolumeId']}] successfully created.")

        # Delete EBS Volume
        if not delete_volume(volume['AccountId'], volume['VolumeId']):
            logger.error(f"PLEASE CHECK: EBS Volume [{volume['VolumeId']}] could not be deleted. Skipping!")

        else:
            logger.info(f"EBS Volume [{volume['VolumeId']}] successfully deleted.")


if __name__ == '__main__':
    main_handler()
