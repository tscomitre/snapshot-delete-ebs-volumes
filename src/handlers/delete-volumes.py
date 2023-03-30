import os
import logging

# Setup logger
logger = logging.getLogger()
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO').upper())


def main_handler(event, context):
    """
    Delete a given EBS Volume
    :param event: (dict) AWS Lambda Function event
    :param context: (dict) AWS Lambda Function context
    """
    logger.debug(f'Lambda Event: {event}')
    logger.debug(f'Lambda Context: {context}')

    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': {'message': f'EBS Volume [X] successfully deleted.'}
    }
