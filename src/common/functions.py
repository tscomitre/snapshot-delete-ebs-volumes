import os
import logging

from utils.aws-functions import

# Setup logger
logger = logging.getLogger()
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO').upper())


def list_aws_accounts():
    """
    Get a list of all the accounts in the AWS Organization
    :return:  A list of all the accounts in the AWS Organization
    """
