import os
import boto3
import logging

# Setup logger
logger = logging.getLogger()
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO').upper())


def create_client(service):
    """
    Creates a service client
    :param service: (string) AWS service which the client will be created for
    :return: client object
    """
    return boto3.client(service)


def list_accounts():
    """
    Lists all the accounts in the organization
    :return: A list of accounts in the organization.
    """
    # Try to list all the accounts in the organization
    try:
        # Create client
        client = create_client('s3')

        # Provide the contents of the request
        client.head_object(
            Bucket=s3_bucket,
            Key=object_key,
            SSECustomerKey=kms_key_id
        )

    # Log an exception if something goes wrong
    except ClientError as ex:
        logger.error('An error has occurred while trying to retrieve the head of an object of S3 Bucket.')
        logger.error(ex)
        return False

    else:
        logger.info('The object key already exists in S3 Bucket. Aborting!')
        return True

    response = client.list_accounts(
        NextToken='string',
        MaxResults=123
    )
client = boto3.client('organizations')