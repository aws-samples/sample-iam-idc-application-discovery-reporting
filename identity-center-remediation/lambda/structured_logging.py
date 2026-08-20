"""
Structured logging module for Identity Center application assignment monitoring.

This module provides JSON-formatted logging with helper functions for each
processing stage. All logs include contextual information for audit and troubleshooting.
"""

import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from enum import Enum


class LogLevel(Enum):
    """Log level enumeration."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class StructuredLogger:
    """
    Structured logger that outputs JSON-formatted log entries.
    
    Each log entry includes:
    - timestamp: ISO 8601 timestamp
    - level: Log level (INFO, WARN, ERROR)
    - message: Human-readable message
    - Additional contextual fields based on the processing stage
    """
    
    def __init__(self, name: str = "identity-center-monitor", level: str = "INFO"):
        """
        Initialize structured logger.
        
        Args:
            name: Logger name
            level: Log level (DEBUG, INFO, WARN, ERROR)
        """
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level))
        
        # Remove existing handlers
        self.logger.handlers = []
        
        # Create console handler with JSON formatter
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(getattr(logging, level))
        
        # Use custom formatter that outputs JSON
        handler.setFormatter(JSONFormatter())
        
        self.logger.addHandler(handler)
        self.logger.propagate = False
    
    def _log(self, level: str, message: str, **kwargs):
        """
        Internal log method that adds structured fields.
        
        Args:
            level: Log level
            message: Human-readable message
            **kwargs: Additional fields to include in log entry
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            "level": level,
            "message": message
        }
        
        # Add all additional fields
        log_entry.update(kwargs)
        
        # Log at appropriate level
        if level == "WARN":
            # Use 'warning' instead of deprecated 'warn'
            self.logger.warning(json.dumps(log_entry))
        else:
            log_method = getattr(self.logger, level.lower())
            log_method(json.dumps(log_entry))
    
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self._log("DEBUG", message, **kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message."""
        self._log("INFO", message, **kwargs)
    
    def warn(self, message: str, **kwargs):
        """Log warning message."""
        self._log("WARN", message, **kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message."""
        self._log("ERROR", message, **kwargs)


class JSONFormatter(logging.Formatter):
    """Custom formatter that outputs JSON."""
    
    def format(self, record):
        """Format log record as JSON string."""
        # The message is already JSON formatted by StructuredLogger
        return record.getMessage()


# Global logger instance
_logger: Optional[StructuredLogger] = None


def get_logger() -> StructuredLogger:
    """
    Get or create the global structured logger instance.
    
    Returns:
        StructuredLogger instance
    """
    global _logger
    if _logger is None:
        _logger = StructuredLogger()
    return _logger


def log_lambda_invocation(event: Dict[str, Any], context: Any = None):
    """
    Log Lambda function invocation with event details.
    
    Args:
        event: EventBridge event payload
        context: Lambda context object (optional)
    """
    logger = get_logger()
    
    log_data = {
        "stage": "invocation",
        "eventType": event.get("detail-type", ""),
        "eventSource": event.get("source", ""),
        "accountId": event.get("account", ""),
        "region": event.get("region", "")
    }
    
    # Add event name if available
    if "detail" in event and "eventName" in event["detail"]:
        log_data["eventName"] = event["detail"]["eventName"]
    
    # Add request ID if context available
    if context:
        log_data["requestId"] = getattr(context, "aws_request_id", "")
    
    logger.info("Lambda function invoked", **log_data)


def log_event_parsing(
    success: bool,
    parsed_data: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None
):
    """
    Log event parsing result.
    
    Args:
        success: Whether parsing was successful
        parsed_data: Parsed event data (if successful)
        error: Error message (if failed)
    """
    logger = get_logger()
    
    log_data = {
        "stage": "event_parsing",
        "success": success
    }
    
    if success and parsed_data:
        log_data.update({
            "applicationArn": parsed_data.get("application_arn", ""),
            "principalDigest": principal_digest(parsed_data.get("principal_id")),
            "principalType": parsed_data.get("principal_type", ""),
            "accountId": parsed_data.get("account_id", ""),
            "eventTime": parsed_data.get("event_time", "")
        })
        logger.info("Event parsed successfully", **log_data)
    else:
        log_data["error"] = error or "Unknown parsing error"
        logger.error("Event parsing failed", **log_data)


def log_validation_result(
    validation_result: Any,
    application_name: str = "",
    group_name: str = ""
):
    """
    Log validation check result with enhanced compliance visibility.
    
    Args:
        validation_result: ValidationResult object or dict
        application_name: Application name (optional, extracted from result if not provided)
        group_name: Group name (optional, extracted from result if not provided)
    """
    logger = get_logger()
    
    # Extract data from validation result
    if hasattr(validation_result, 'to_dict'):
        result_dict = validation_result.to_dict()
    elif isinstance(validation_result, dict):
        result_dict = validation_result
    else:
        result_dict = {
            'is_compliant': getattr(validation_result, 'is_compliant', False),
            'application_name': getattr(validation_result, 'application_name', application_name),
            'group_name': getattr(validation_result, 'group_name', group_name),
            'reason': getattr(validation_result, 'reason', '')
        }
    
    is_compliant = result_dict.get('is_compliant', False)
    app_name = result_dict.get('application_name', application_name)
    grp_name = result_dict.get('group_name', group_name)
    reason = result_dict.get('reason', '')
    
    # Enhanced log data with explicit compliance indicators
    log_data = {
        "stage": "validation",
        "isCompliant": is_compliant,
        "complianceStatus": "COMPLIANT" if is_compliant else "NON_COMPLIANT",
        "applicationName": app_name,
        "groupName": grp_name,
        "validationReason": reason
    }
    
    # matchFound carries the verdict. There is deliberately no complianceDetail
    # field: it restated groupName, applicationName and matchFound in prose, so it
    # was a second copy of the group name -- a resolved Identity Store display
    # name, which is an email address for a directory federated from an
    # email-based source -- in every compliance log entry. Removing it drops the
    # duplicate without losing anything an operator can act on.
    #
    # groupName itself is kept unredacted, and that is a decision rather than an
    # oversight: this entry is the compliance alert. One that will not say which
    # group was assigned cannot be triaged. The consequence is that this log group
    # holds personal data, so scope who can read it -- the same reasoning applies
    # to the SNS topic in the reporting stack.
    if is_compliant:
        log_data["matchFound"] = True
        logger.info("✓ COMPLIANT - Group name found in application name", **log_data)
    else:
        log_data["matchFound"] = False
        logger.warn("✗ NON-COMPLIANT - Group name not found in application name", **log_data)


def principal_digest(principal_id: Optional[str]) -> str:
    """
    Reduce a principal identifier to a short, non-reversible digest.

    A raw Identity Store principal ID in a log line states which specific person
    held which access. The digest is stable, so entries for the same principal still
    correlate across the parse/attempt/result stages of one deletion, and an
    operator who needs the real identifier has CloudTrail's record of the
    DeleteApplicationAssignment call -- which is the authoritative audit trail for a
    destructive action, and is access-controlled.

    This is deliberately unlike the groupName decision below, where the resolved
    name IS the alert and is kept. Here the principal ID is a join key, and a digest
    joins just as well.
    """
    if not principal_id:
        return ""
    return hashlib.sha256(str(principal_id).encode("utf-8")).hexdigest()[:12]


def log_remediation_action(
    action: str,
    validation_result: Any = None,
    enable_auto_deletion: bool = False
):
    """
    Log remediation action determination.
    
    Args:
        action: Remediation action (NONE, NOTIFICATION_ONLY, DELETED)
        validation_result: ValidationResult object (optional)
        enable_auto_deletion: Whether auto-deletion is enabled
    """
    logger = get_logger()
    
    log_data = {
        "stage": "remediation_decision",
        "action": action,
        "autoDeleteEnabled": enable_auto_deletion
    }
    
    if validation_result:
        if hasattr(validation_result, 'is_compliant'):
            log_data["isCompliant"] = validation_result.is_compliant
    
    logger.info(f"Remediation action determined: {action}", **log_data)


def log_deletion_attempt(
    application_arn: str,
    principal_id: str,
    principal_type: str
):
    """
    Log deletion attempt.
    
    Args:
        application_arn: Application ARN
        principal_id: Principal ID
        principal_type: Principal type (USER or GROUP)
    """
    logger = get_logger()
    
    log_data = {
        "stage": "deletion",
        "action": "attempting_deletion",
        "applicationArn": application_arn,
        "principalDigest": principal_digest(principal_id),
        "principalType": principal_type
    }
    
    logger.info("Attempting to delete application assignment", **log_data)


def log_deletion_result(deletion_result: Any):
    """
    Log deletion operation result.
    
    Args:
        deletion_result: DeletionResult object or dict
    """
    logger = get_logger()
    
    # Extract data from deletion result
    if hasattr(deletion_result, 'to_dict'):
        result_dict = deletion_result.to_dict()
    elif isinstance(deletion_result, dict):
        result_dict = deletion_result
    else:
        result_dict = {
            'success': getattr(deletion_result, 'success', False),
            'application_arn': getattr(deletion_result, 'application_arn', ''),
            'principal_id': getattr(deletion_result, 'principal_id', ''),
            'error_message': getattr(deletion_result, 'error_message', None),
            'error_code': getattr(deletion_result, 'error_code', None)
        }
    
    log_data = {
        "stage": "deletion",
        "action": "deletion_result",
        "success": result_dict.get('success', False),
        "applicationArn": result_dict.get('application_arn', ''),
        "principalDigest": principal_digest(result_dict.get('principal_id'))
    }
    
    if not result_dict.get('success'):
        log_data["errorCode"] = result_dict.get('error_code', '')
        log_data["errorMessage"] = result_dict.get('error_message', '')
        logger.error("Deletion failed", **log_data)
    else:
        logger.info("Deletion successful", **log_data)


def log_notification_sent(
    success: bool,
    action: str,
    status: str,
    application_name: str = "",
    group_name: str = "",
    error: Optional[str] = None
):
    """
    Log SNS notification result.
    
    Args:
        success: Whether notification was sent successfully
        action: Action taken (DELETED or NOTIFICATION_ONLY)
        status: Status (SUCCESS or FAILED)
        application_name: Application name
        group_name: Group name
        error: Error message if failed
    """
    logger = get_logger()
    
    log_data = {
        "stage": "notification",
        "success": success,
        "action": action,
        "status": status,
        "applicationName": application_name,
        "groupName": group_name
    }
    
    if not success and error:
        log_data["error"] = error
        logger.error("Failed to send SNS notification", **log_data)
    else:
        logger.info("SNS notification sent successfully", **log_data)


def log_error(
    error_message: str,
    error_type: str = "UnexpectedError",
    stage: str = "unknown",
    stack_trace: Optional[str] = None,
    **context
):
    """
    Log error with full context and stack trace.
    
    Args:
        error_message: Error message
        error_type: Type of error (e.g., ParsingError, APIError)
        stage: Processing stage where error occurred
        stack_trace: Stack trace string (optional)
        **context: Additional context fields
    """
    logger = get_logger()
    
    log_data = {
        "stage": stage,
        "errorType": error_type,
        "errorMessage": error_message
    }
    
    if stack_trace:
        log_data["stackTrace"] = stack_trace
    
    # Add any additional context
    log_data.update(context)
    
    logger.error(f"Error in {stage}: {error_message}", **log_data)


def log_processing_complete(
    success: bool,
    action_taken: str = "NONE",
    duration_ms: Optional[float] = None
):
    """
    Log completion of event processing.
    
    Args:
        success: Whether processing completed successfully
        action_taken: Action that was taken (NONE, NOTIFICATION_ONLY, DELETED)
        duration_ms: Processing duration in milliseconds (optional)
    """
    logger = get_logger()
    
    log_data = {
        "stage": "completion",
        "success": success,
        "actionTaken": action_taken
    }
    
    if duration_ms is not None:
        log_data["durationMs"] = duration_ms
    
    if success:
        logger.info("Event processing completed successfully", **log_data)
    else:
        logger.error("Event processing completed with errors", **log_data)
