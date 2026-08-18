"""
SNS client wrapper for sending notifications.

This module provides a wrapper around boto3 SNS client for publishing
notifications about non-compliant assignments.
"""

import json
from datetime import datetime
from typing import Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
from retry import retry_with_backoff


class SNSClient:
    """Wrapper for AWS SNS client with retry logic."""
    
    def __init__(self, topic_arn: str):
        """
        Initialize SNS client.
        
        Args:
            topic_arn: ARN of SNS topic to publish to
        """
        self.topic_arn = topic_arn
        self.client = boto3.client('sns')
    
    @retry_with_backoff(max_attempts=3, base_delay=1.0)
    def publish_message(self, subject: str, message: str) -> Dict[str, Any]:
        """
        Publish a message to the SNS topic with retry logic.
        
        Args:
            subject: Subject line for the notification
            message: Message body (JSON formatted string)
            
        Returns:
            Response from SNS publish operation
            
        Raises:
            ClientError: If publish fails after all retries
        """
        response = self.client.publish(
            TopicArn=self.topic_arn,
            Subject=subject,
            Message=message
        )
        return response


def build_notification_message(
    application_name: str,
    group_name: str,
    account_id: str,
    timestamp: str,
    action: str,
    status: str,
    application_arn: Optional[str] = None,
    principal_id: Optional[str] = None,
    error_message: Optional[str] = None,
    user_identity: Optional[Dict[str, str]] = None
) -> str:
    """
    Build notification message payload.
    
    Args:
        application_name: Name of the Identity Center application
        group_name: Name of the Identity Center group (display name)
        account_id: AWS account ID where event originated
        timestamp: ISO 8601 timestamp of the event
        action: Action taken (DELETED or NOTIFICATION_ONLY)
        status: Status of the action (SUCCESS or FAILED)
        application_arn: Optional application ARN
        principal_id: Optional principal (group) ID
        error_message: Optional error message if status is FAILED
        user_identity: Optional IAM principal information who initiated the change
        
    Returns:
        JSON formatted message string
    """
    message_data = {
        "timestamp": timestamp,
        "eventType": "NON_COMPLIANT_ASSIGNMENT",
        "accountId": account_id,
        "applicationName": application_name,
        "groupName": group_name,
        "action": action,
        "status": status
    }
    
    # Add optional fields if provided
    if application_arn:
        message_data["applicationArn"] = application_arn
    
    if principal_id:
        message_data["groupId"] = principal_id  # Changed from principalId to groupId for clarity
    
    if user_identity:
        message_data["initiatedBy"] = {
            "type": user_identity.get('type', 'Unknown'),
            "arn": user_identity.get('arn', 'Unknown'),
            "principalId": user_identity.get('principalId', 'Unknown'),
            "accountId": user_identity.get('accountId', 'Unknown')
        }
    
    if error_message:
        message_data["errorMessage"] = error_message
    
    return json.dumps(message_data, indent=2)


def build_subject_line(action: str, status: str) -> str:
    """
    Build subject line for notification.
    
    Args:
        action: Action taken (DELETED or NOTIFICATION_ONLY)
        status: Status of the action (SUCCESS or FAILED)
        
    Returns:
        Subject line string
    """
    if status == "FAILED":
        return "[Identity Center] ERROR: Failed to process assignment"
    
    if action == "DELETED":
        return "[Identity Center] Non-compliant assignment DELETED"
    elif action == "NOTIFICATION_ONLY":
        return "[Identity Center] Non-compliant assignment NOTIFICATION_ONLY"
    else:
        return "[Identity Center] Non-compliant assignment detected"


def send_notification(
    sns_client: SNSClient,
    application_name: str,
    group_name: str,
    account_id: str,
    action: str,
    status: str,
    application_arn: Optional[str] = None,
    principal_id: Optional[str] = None,
    error_message: Optional[str] = None,
    timestamp: Optional[str] = None,
    user_identity: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Send notification about non-compliant assignment.
    
    Args:
        sns_client: SNS client instance
        application_name: Name of the Identity Center application
        group_name: Name of the Identity Center group
        account_id: AWS account ID where event originated
        action: Action taken (DELETED or NOTIFICATION_ONLY)
        status: Status of the action (SUCCESS or FAILED)
        application_arn: Optional application ARN
        principal_id: Optional principal (group) ID
        error_message: Optional error message if status is FAILED
        timestamp: Optional ISO 8601 timestamp (defaults to current time)
        user_identity: Optional IAM principal information who initiated the change
        
    Returns:
        Response from SNS publish operation
    """
    # Use current time if timestamp not provided
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat() + 'Z'
    
    # Build message and subject
    message = build_notification_message(
        application_name=application_name,
        group_name=group_name,
        account_id=account_id,
        timestamp=timestamp,
        action=action,
        status=status,
        application_arn=application_arn,
        principal_id=principal_id,
        error_message=error_message,
        user_identity=user_identity
    )
    
    subject = build_subject_line(action=action, status=status)
    
    # Publish to SNS
    return sns_client.publish_message(subject=subject, message=message)
