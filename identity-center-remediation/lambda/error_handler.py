"""
Error handling module for Lambda function.

This module provides global exception handling, error categorization,
and error notification building for the Identity Center application monitor.
"""

import json
import logging
import traceback
from typing import Dict, Any, Optional
from enum import Enum
from datetime import datetime, timezone
from structured_logging import principal_digest

logger = logging.getLogger(__name__)


class ErrorCategory(Enum):
    """Categories of errors that can occur during processing."""
    TRANSIENT = "TRANSIENT"  # Retryable errors (throttling, service unavailable)
    PERMANENT = "PERMANENT"  # Non-retryable errors (access denied, not found)
    PARSING = "PARSING"  # Event parsing errors
    UNEXPECTED = "UNEXPECTED"  # Unexpected exceptions


class ErrorSeverity(Enum):
    """Severity levels for errors."""
    HIGH = "HIGH"  # Critical errors requiring immediate attention
    MEDIUM = "MEDIUM"  # Important errors that should be reviewed
    LOW = "LOW"  # Minor errors or warnings


def categorize_error(exception: Exception) -> ErrorCategory:
    """
    Categorize an exception into one of the defined error categories.
    
    Args:
        exception: Exception to categorize
        
    Returns:
        ErrorCategory enum value
    """
    from botocore.exceptions import ClientError
    from event_parser import EventParsingError
    
    # Check for parsing errors (including wrapped exceptions)
    if isinstance(exception, EventParsingError):
        return ErrorCategory.PARSING
    
    # Check for AWS service errors
    if isinstance(exception, ClientError):
        error_code = exception.response.get('Error', {}).get('Code', '')
        
        # Transient errors
        if error_code in {
            'ThrottlingException',
            'InternalServerException',
            'ServiceUnavailableException',
            'RequestTimeout',
            'InternalFailure',
            'ServiceUnavailable'
        }:
            return ErrorCategory.TRANSIENT
        
        # Permanent errors
        if error_code in {
            'AccessDeniedException',
            'ResourceNotFoundException',
            'ValidationException',
            'InvalidParameterException',
            'UnauthorizedException'
        }:
            return ErrorCategory.PERMANENT
    
    # Check for common Python exceptions that indicate parsing issues
    if isinstance(exception, (KeyError, ValueError, TypeError, json.JSONDecodeError)):
        return ErrorCategory.PARSING
    
    # Check if this is a wrapped parsing error by examining the cause chain
    if hasattr(exception, '__cause__') and exception.__cause__:
        cause_category = categorize_error(exception.__cause__)
        if cause_category == ErrorCategory.PARSING:
            return ErrorCategory.PARSING
    
    # Default to unexpected for unknown errors
    return ErrorCategory.UNEXPECTED


def determine_severity(error_category: ErrorCategory) -> ErrorSeverity:
    """
    Determine the severity level based on error category.
    
    Args:
        error_category: Category of the error
        
    Returns:
        ErrorSeverity enum value
    """
    severity_map = {
        ErrorCategory.TRANSIENT: ErrorSeverity.MEDIUM,
        ErrorCategory.PERMANENT: ErrorSeverity.HIGH,
        ErrorCategory.PARSING: ErrorSeverity.MEDIUM,
        ErrorCategory.UNEXPECTED: ErrorSeverity.HIGH
    }
    return severity_map.get(error_category, ErrorSeverity.HIGH)


def build_error_notification(
    exception: Exception,
    context: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None
) -> Dict[str, Any]:
    """
    Build a structured error notification message.
    
    Args:
        exception: Exception that occurred
        context: Optional context information (event details, etc.)
        timestamp: Optional ISO 8601 timestamp (defaults to current time)
        
    Returns:
        Dictionary containing error notification data
    """
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    if context is None:
        context = {}
    
    # Categorize the error
    error_category = categorize_error(exception)
    severity = determine_severity(error_category)
    
    # The stack trace goes to CloudWatch, not into the notification.
    #
    # This payload is published to SNS with shouldNotify=True, so it reaches every
    # subscriber -- email, SMS, whatever is attached. A traceback carries whatever
    # the exception message happened to interpolate, and in this codebase that is
    # routinely a principal ID or an application ARN. CloudWatch access is gated by
    # IAM; an SNS subscription list is not, so the trace belongs in the log and a
    # bounded summary belongs in the notification.
    logger.error(
        "Error notification built for %s: %s",
        type(exception).__name__,
        traceback.format_exc(),
    )

    notification = {
        "timestamp": timestamp,
        "eventType": "ERROR",
        "severity": severity.value,
        "errorCategory": error_category.value,
        "errorMessage": str(exception),
        "errorType": type(exception).__name__,
        "context": context
    }

    return notification


def format_error_notification_message(notification: Dict[str, Any]) -> str:
    """
    Format error notification as JSON string.
    
    Args:
        notification: Error notification dictionary
        
    Returns:
        JSON formatted string
    """
    return json.dumps(notification, indent=2)


def build_error_subject_line(error_category: ErrorCategory, severity: ErrorSeverity) -> str:
    """
    Build subject line for error notification.
    
    Args:
        error_category: Category of the error
        severity: Severity level of the error
        
    Returns:
        Subject line string
    """
    return f"[Identity Center] {severity.value}: {error_category.value} Error"


def handle_malformed_event(event: Dict[str, Any], exception: Exception) -> Dict[str, Any]:
    """
    Handle malformed event payloads gracefully.
    
    When an event cannot be parsed or is missing required fields, this function
    creates an error notification without attempting remediation.
    
    Args:
        event: The malformed event payload
        exception: The parsing exception that occurred
        
    Returns:
        Dictionary containing error details and notification data
    """
    # Extract whatever context we can from the malformed event
    context = {
        "eventId": event.get('id', 'unknown'),
        "eventSource": event.get('source', 'unknown'),
        "eventTime": event.get('time', 'unknown')
    }
    
    # Try to extract account ID if available
    if 'account' in event:
        context['accountId'] = event['account']
    
    # Try to extract detail if available
    if 'detail' in event:
        detail = event['detail']
        if isinstance(detail, dict):
            context['eventName'] = detail.get('eventName', 'unknown')
    
    # Build error notification
    notification = build_error_notification(
        exception=exception,
        context=context
    )
    
    return {
        "error": notification,
        "shouldNotify": True,
        "shouldRemediate": False
    }


def handle_global_exception(
    exception: Exception,
    event: Optional[Dict[str, Any]] = None,
    parsed_data: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Global exception handler for unexpected errors.
    
    Catches any unexpected exception, logs it with full context, and builds
    an error notification. Ensures the Lambda function completes gracefully
    without crashing.
    
    Args:
        exception: The exception that occurred
        event: Optional original event payload
        parsed_data: Optional parsed event data (if parsing succeeded)
        
    Returns:
        Dictionary containing error details and notification data
    """
    # Build context from available information
    context = {}
    
    if event:
        context['eventId'] = event.get('id', 'unknown')
        context['eventSource'] = event.get('source', 'unknown')
        context['accountId'] = event.get('account', 'unknown')
    
    if parsed_data:
        context['applicationArn'] = parsed_data.get('application_arn', 'unknown')
        # Digest, not the raw ID: this context is embedded in the SNS notification.
        context['principalDigest'] = principal_digest(parsed_data.get('principal_id'))
        context['accountId'] = parsed_data.get('account_id', context.get('accountId', 'unknown'))
    
    # Build error notification
    notification = build_error_notification(
        exception=exception,
        context=context
    )
    
    return {
        "error": notification,
        "shouldNotify": True,
        "shouldRemediate": False
    }
