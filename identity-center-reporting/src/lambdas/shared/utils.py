# Shared utilities for IAM Identity Center Discovery Solution

import logging
import json
import boto3
import time
import random
from typing import Dict, Any, Optional, Callable
from botocore.exceptions import ClientError, BotoCoreError

def setup_logging(name: str, level: str = "INFO") -> logging.Logger:
    """
    Set up standardized logging configuration
    
    Args:
        name: Logger name (typically __name__)
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger

def handle_api_error(error: Exception) -> Dict[str, Any]:
    """
    Standardized error handling for Lambda functions
    
    Args:
        error: Exception that occurred
    
    Returns:
        Standardized error response
    """
    if isinstance(error, ClientError):
        error_code = error.response['Error']['Code']
        error_message = error.response['Error']['Message']
        
        return {
            'statusCode': 400 if error_code in ['ValidationException', 'InvalidParameterException'] else 500,
            'body': json.dumps({
                'error': error_code,
                'message': error_message
            })
        }
    
    logger = logging.getLogger(__name__)
    logger.error(f"Unhandled error: {str(error)}")
    return {
        'statusCode': 500,
        'body': json.dumps({
            'error': 'InternalError',
            'message': 'An unexpected error occurred. Check CloudWatch logs for details.'
        })
    }


def handle_access_denied_exception(error: Exception, context: Any, resource_arn: str = None) -> Dict[str, Any]:
    """
    Handle AccessDeniedException with detailed logging and structured error response.

    Logs full details server-side but returns a sanitized response to callers.

    Args:
        error: The AccessDeniedException from boto3
        context: Lambda context object
        resource_arn: The resource ARN that was being accessed

    Returns:
        Structured error response with actionable information
    """
    logger = logging.getLogger(__name__)

    error_response = getattr(error, 'response', {})
    error_details = error_response.get('Error', {})
    error_message = error_details.get('Message', str(error))

    # Extract the action from the error message if possible
    missing_permission = None
    if 'is not authorized to perform:' in error_message:
        try:
            parts = error_message.split('is not authorized to perform:')
            if len(parts) > 1:
                action_part = parts[1].split('on resource:')[0].strip()
                missing_permission = action_part
        except Exception:
            pass

    # Get request ID for tracking
    request_id = error_response.get('ResponseMetadata', {}).get('RequestId', 'N/A')

    # Get Lambda function name from context
    function_name = getattr(context, 'function_name', 'unknown')

    # Log comprehensive error information server-side
    logger.error("=" * 80)
    logger.error("ACCESS DENIED ERROR DETECTED")
    logger.error("=" * 80)
    logger.error(f"Lambda Function: {function_name}")
    logger.error(f"Missing Permission: {missing_permission or 'Unable to determine'}")
    logger.error(f"Resource ARN: {resource_arn or 'Unable to determine'}")
    logger.error(f"Request ID: {request_id}")
    logger.error(f"Full Error Message: {error_message}")
    logger.error("=" * 80)
    logger.error("ACTION REQUIRED:")
    logger.error("1. Update the Lambda execution role IAM policy")
    logger.error(f"2. Add permission: {missing_permission or '<action>'}")
    logger.error(f"3. For resource: {resource_arn or '<resource>'}")
    logger.error("=" * 80)

    return {
        'statusCode': 403,
        'body': json.dumps({
            'success': False,
            'message': 'Access denied: Missing required IAM permissions. Check CloudWatch logs for details.',
            'request_id': request_id,
            'applications': [],
            'assignments': [],
            'errors': ['Access denied: insufficient IAM permissions'],
            'count': 0,
            'assignment_count': 0
        })
    }

def get_aws_client(service_name: str, region: Optional[str] = None, role_arn: Optional[str] = None) -> boto3.client:
    """
    Create AWS service client with optional cross-account role assumption
    
    Args:
        service_name: AWS service name (e.g., 'sso-admin', 'organizations')
        region: AWS region (defaults to current region)
        role_arn: Optional IAM role ARN for cross-account access
    
    Returns:
        Configured boto3 client
    """
    session = boto3.Session()
    
    if role_arn:
        sts_client = session.client('sts')
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='iam-identity-center-discovery',
            ExternalId='iam-identity-center-discovery'  # Required by cross-account role
        )
        
        credentials = assumed_role['Credentials']
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    
    return session.client(service_name, region_name=region)

def redact_principal(value: Optional[str], keep: int = 8) -> str:
    """
    Shorten a principal identifier for logging.

    Discovery logs run at scale and on repeat: a single sync-drift event can emit
    the same principal on every run. A full Identity Store principal ID next to an
    application ARN says which specific person holds which access, and a resolved
    principal *name* is worse still, because in a directory federated from an
    email-based identity source that name is an email address. Neither belongs in
    CloudWatch at INFO or DEBUG.

    Keeping a prefix leaves the logs useful -- entries for the same principal still
    correlate across lines, and an operator can look the full value up deliberately
    from the DynamoDB record -- without the log stream itself becoming a roster.

    Args:
        value: Principal ID, name, or email. May be None.
        keep: Number of leading characters to retain.

    Returns:
        Truncated value with an ellipsis, or 'unknown' when there is nothing to log.
    """
    if not value:
        return "unknown"
    text = str(value)
    if len(text) <= keep:
        return text
    return f"{text[:keep]}..."


def scan_all(table, **kwargs) -> list:
    """
    Scan a DynamoDB table and return EVERY item, following LastEvaluatedKey.

    A bare table.scan() returns at most 1 MB of items. Treating that first page
    as the complete table silently under-reports: change detection re-classifies
    everything beyond page one as newly created on every run, and stale-record
    cleanup never sees the rows it should remove. Both failure modes look like
    success, which is why they need a paginating helper rather than a bare call.

    Args:
        table: boto3 DynamoDB Table resource
        **kwargs: additional Scan parameters (FilterExpression, etc.)

    Returns:
        List of all items across every page
    """
    items = []
    start_key = None
    while True:
        params = dict(kwargs)
        if start_key:
            params['ExclusiveStartKey'] = start_key
        response = table.scan(**params)
        items.extend(response.get('Items', []))
        start_key = response.get('LastEvaluatedKey')
        if not start_key:
            return items


def query_all(table, **kwargs) -> list:
    """
    Query a DynamoDB table and return EVERY item, following LastEvaluatedKey.

    Same 1 MB page limit as Scan. A partition with more than one page of
    dependents would otherwise yield a partial result set with no error.

    Args:
        table: boto3 DynamoDB Table resource
        **kwargs: Query parameters (KeyConditionExpression, IndexName, etc.)

    Returns:
        List of all items across every page
    """
    items = []
    start_key = None
    while True:
        params = dict(kwargs)
        if start_key:
            params['ExclusiveStartKey'] = start_key
        response = table.query(**params)
        items.extend(response.get('Items', []))
        start_key = response.get('LastEvaluatedKey')
        if not start_key:
            return items


def paginate_api_call(client: boto3.client, operation_name: str, **kwargs) -> list:
    """
    Handle AWS API pagination automatically with retry logic
    
    Args:
        client: Boto3 client instance
        operation_name: API operation name
        **kwargs: API operation parameters
    
    Returns:
        List of all paginated results
    """
    def _paginate():
        paginator = client.get_paginator(operation_name)
        results = []
        
        for page in paginator.paginate(**kwargs):
            # Extract the main result key (varies by API)
            for key, value in page.items():
                if isinstance(value, list) and key != 'ResponseMetadata':
                    results.extend(value)
                    break
        
        return results
    
    return retry_with_exponential_backoff(_paginate)

def retry_with_exponential_backoff(
    func: Callable,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    backoff_multiplier: float = 2.0,
    jitter: bool = True
) -> Any:
    """
    Retry a function with exponential backoff
    
    Args:
        func: Function to retry
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
        backoff_multiplier: Multiplier for exponential backoff
        jitter: Whether to add random jitter to delay
    
    Returns:
        Result of the function call
    
    Raises:
        Last exception encountered if all retries fail
    """
    logger = logging.getLogger(__name__)
    
    for attempt in range(max_retries + 1):
        try:
            return func()
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            # Don't retry on certain error types
            if error_code in ['AccessDeniedException', 'ValidationException', 'InvalidParameterException']:
                logger.warning(f"Non-retryable error: {error_code} - {e.response['Error']['Message']}")
                raise
            
            # Retry on throttling and server errors
            if error_code in ['Throttling', 'ThrottlingException', 'TooManyRequestsException', 'ServiceUnavailable', 'InternalServerError']:
                if attempt < max_retries:
                    delay = min(base_delay * (backoff_multiplier ** attempt), max_delay)
                    if jitter:
                        delay *= (0.5 + random.random() * 0.5)  # Add 0-50% jitter
                    
                    logger.warning(f"Throttling detected ({error_code}), retrying in {delay:.2f} seconds (attempt {attempt + 1}/{max_retries + 1})")
                    time.sleep(delay)
                    continue
                else:
                    logger.error(f"Max retries exceeded for throttling error: {error_code}")
                    raise
            else:
                # For other client errors, don't retry
                logger.error(f"Client error: {error_code} - {e.response['Error']['Message']}")
                raise
                
        except BotoCoreError as e:
            # Retry on network/connection errors
            if attempt < max_retries:
                delay = min(base_delay * (backoff_multiplier ** attempt), max_delay)
                if jitter:
                    delay *= (0.5 + random.random() * 0.5)
                
                logger.warning(f"Network error, retrying in {delay:.2f} seconds (attempt {attempt + 1}/{max_retries + 1}): {str(e)}")
                time.sleep(delay)
                continue
            else:
                logger.error(f"Max retries exceeded for network error: {str(e)}")
                raise
                
        except Exception as e:
            # For unexpected errors, don't retry
            logger.error(f"Unexpected error (not retrying): {str(e)}")
            raise
    
    # This should never be reached, but just in case
    raise Exception("Retry logic error: exceeded maximum attempts without raising exception")

def safe_api_call(func: Callable, error_context: str = "", continue_on_error: bool = True) -> tuple:
    """
    Safely execute an API call with proper error handling and logging
    
    Args:
        func: Function to execute
        error_context: Context string for error logging
        continue_on_error: Whether to continue processing on error
    
    Returns:
        Tuple of (success: bool, result: Any, error: str)
    """
    logger = logging.getLogger(__name__)
    
    try:
        result = retry_with_exponential_backoff(func)
        return True, result, None
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        full_error = f"{error_context}: {error_code} - {error_message}"
        
        if continue_on_error:
            logger.warning(full_error)
        else:
            logger.error(full_error)
        
        return False, None, full_error
    except Exception as e:
        full_error = f"{error_context}: {str(e)}"
        
        if continue_on_error:
            logger.warning(full_error)
        else:
            logger.error(full_error)
        
        return False, None, full_error