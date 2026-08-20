"""
Property-based tests for SNS notification system.

**Feature: identity-center-app-monitor, Property 5: SNS notification on non-compliance**
**Validates: Requirements 4.1**
"""

import pytest
import json
from structured_logging import principal_digest
from unittest.mock import Mock, MagicMock, patch
from hypothesis import given, strategies as st, settings, assume
from datetime import datetime
from botocore.exceptions import ClientError

from sns_client import (
    SNSClient,
    build_notification_message,
    build_subject_line,
    send_notification
)
from validation import ValidationResult


# Strategy for generating valid application names
application_names = st.text(
    alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-_'),
    min_size=1,
    max_size=100
)

# Strategy for generating valid group names
group_names = st.text(
    alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), whitelist_characters='-_'),
    min_size=1,
    max_size=100
)

# Strategy for generating AWS account IDs
account_ids = st.text(
    alphabet=st.characters(whitelist_categories=('Nd',)),
    min_size=12,
    max_size=12
)

# Strategy for generating ISO 8601 timestamps
timestamps = st.datetimes(
    min_value=datetime(2020, 1, 1),
    max_value=datetime(2030, 12, 31)
).map(lambda dt: dt.isoformat() + 'Z')

# Strategy for actions
actions = st.sampled_from(['DELETED', 'NOTIFICATION_ONLY'])

# Strategy for status
statuses = st.sampled_from(['SUCCESS', 'FAILED'])



class TestSNSNotificationOnNonCompliance:
    """
    Tests for Property 5: SNS notification on non-compliance.
    
    For any non-compliant assignment detected, the system should publish
    exactly one message to the SNS topic.
    """
    
    @given(
        application_name=application_names,
        group_name=group_names,
        account_id=account_ids,
        timestamp=timestamps,
        action=actions,
        status=statuses
    )
    @settings(max_examples=100)
    def test_notification_sent_for_non_compliant_assignment(
        self,
        application_name,
        group_name,
        account_id,
        timestamp,
        action,
        status
    ):
        """
        **Property 5: SNS notification on non-compliance**
        
        For any non-compliant assignment (where group name is not in application name),
        the system should publish exactly one message to the SNS topic.
        """
        # Ensure non-compliant: group name not in application name
        assume(group_name.lower() not in application_name.lower())
        
        # Create mock SNS client
        mock_sns_client = Mock(spec=SNSClient)
        mock_sns_client.publish_message = Mock(return_value={'MessageId': 'test-message-id'})
        
        # Send notification
        result = send_notification(
            sns_client=mock_sns_client,
            application_name=application_name,
            group_name=group_name,
            account_id=account_id,
            action=action,
            status=status,
            timestamp=timestamp
        )
        
        # Verify publish_message was called exactly once
        assert mock_sns_client.publish_message.call_count == 1
        
        # Verify the call was made with correct parameters
        call_args = mock_sns_client.publish_message.call_args
        assert call_args is not None
        
        # Extract subject and message from call
        subject = call_args[1]['subject']
        message = call_args[1]['message']
        
        # Verify subject is not empty
        assert len(subject) > 0
        
        # Verify message is valid JSON
        message_data = json.loads(message)
        
        # Verify message contains required fields
        assert message_data['applicationName'] == application_name
        assert message_data['groupName'] == group_name
        assert message_data['accountId'] == account_id
        assert message_data['action'] == action
        assert message_data['status'] == status
        assert message_data['timestamp'] == timestamp
    
    @given(
        application_name=application_names,
        group_name=group_names,
        account_id=account_ids,
        action=actions
    )
    @settings(max_examples=100)
    def test_notification_includes_all_required_fields(
        self,
        application_name,
        group_name,
        account_id,
        action
    ):
        """
        **Property 5: SNS notification on non-compliance**
        
        For any non-compliant assignment, the notification message should
        include all required fields: application name, group name, account ID,
        timestamp, action, and status.
        """
        # Ensure non-compliant
        assume(group_name.lower() not in application_name.lower())
        
        # Build notification message
        timestamp = datetime.utcnow().isoformat() + 'Z'
        message = build_notification_message(
            application_name=application_name,
            group_name=group_name,
            account_id=account_id,
            timestamp=timestamp,
            action=action,
            status='SUCCESS'
        )
        
        # Parse message
        message_data = json.loads(message)
        
        # Verify all required fields are present
        assert 'applicationName' in message_data
        assert 'groupName' in message_data
        assert 'accountId' in message_data
        assert 'timestamp' in message_data
        assert 'action' in message_data
        assert 'status' in message_data
        assert 'eventType' in message_data
        
        # Verify field values
        assert message_data['applicationName'] == application_name
        assert message_data['groupName'] == group_name
        assert message_data['accountId'] == account_id
        assert message_data['action'] == action
        assert message_data['status'] == 'SUCCESS'
        assert message_data['eventType'] == 'NON_COMPLIANT_ASSIGNMENT'
    
    @given(
        application_name=application_names,
        group_name=group_names,
        account_id=account_ids
    )
    @settings(max_examples=100)
    def test_notification_sent_only_once_per_assignment(
        self,
        application_name,
        group_name,
        account_id
    ):
        """
        **Property 5: SNS notification on non-compliance**
        
        For any non-compliant assignment, exactly one notification should be sent,
        not multiple notifications for the same assignment.
        """
        # Ensure non-compliant
        assume(group_name.lower() not in application_name.lower())
        
        # Create mock SNS client
        mock_sns_client = Mock(spec=SNSClient)
        mock_sns_client.publish_message = Mock(return_value={'MessageId': 'test-message-id'})
        
        # Send notification once
        send_notification(
            sns_client=mock_sns_client,
            application_name=application_name,
            group_name=group_name,
            account_id=account_id,
            action='NOTIFICATION_ONLY',
            status='SUCCESS'
        )
        
        # Verify exactly one call was made
        assert mock_sns_client.publish_message.call_count == 1



class TestCompleteNotificationMessageFormat:
    """
    Tests for Property 6: Complete notification message format.
    
    For any SNS notification published, the message should include application name,
    group name, account ID, timestamp, action taken (DELETED or NOTIFICATION_ONLY),
    and status (SUCCESS or FAILED).
    
    **Feature: identity-center-app-monitor, Property 6: Complete notification message format**
    **Validates: Requirements 4.2, 4.3, 10.3, 10.4**
    """
    
    @given(
        application_name=application_names,
        group_name=group_names,
        account_id=account_ids,
        timestamp=timestamps,
        action=actions,
        status=statuses
    )
    @settings(max_examples=100)
    def test_message_contains_all_required_fields(
        self,
        application_name,
        group_name,
        account_id,
        timestamp,
        action,
        status
    ):
        """
        **Property 6: Complete notification message format**
        
        For any SNS notification, the message should include all required fields:
        application name, group name, account ID, timestamp, action, and status.
        """
        # Build notification message
        message = build_notification_message(
            application_name=application_name,
            group_name=group_name,
            account_id=account_id,
            timestamp=timestamp,
            action=action,
            status=status
        )
        
        # Parse message as JSON
        message_data = json.loads(message)
        
        # Verify all required fields are present
        required_fields = [
            'applicationName',
            'groupName',
            'accountId',
            'timestamp',
            'action',
            'status',
            'eventType'
        ]
        
        for field in required_fields:
            assert field in message_data, f"Required field '{field}' missing from message"
        
        # Verify field values match inputs
        assert message_data['applicationName'] == application_name
        assert message_data['groupName'] == group_name
        assert message_data['accountId'] == account_id
        assert message_data['timestamp'] == timestamp
        assert message_data['action'] == action
        assert message_data['status'] == status
        assert message_data['eventType'] == 'NON_COMPLIANT_ASSIGNMENT'
    
    @given(
        application_name=application_names,
        group_name=group_names,
        account_id=account_ids,
        timestamp=timestamps,
        action=actions
    )
    @settings(max_examples=100)
    def test_message_format_for_success_status(
        self,
        application_name,
        group_name,
        account_id,
        timestamp,
        action
    ):
        """
        **Property 6: Complete notification message format**
        
        For any successful notification (status=SUCCESS), the message should
        include all required fields and not include an error message.
        """
        # Build notification message with SUCCESS status
        message = build_notification_message(
            application_name=application_name,
            group_name=group_name,
            account_id=account_id,
            timestamp=timestamp,
            action=action,
            status='SUCCESS'
        )
        
        # Parse message
        message_data = json.loads(message)
        
        # Verify status is SUCCESS
        assert message_data['status'] == 'SUCCESS'
        
        # Verify all required fields are present
        assert 'applicationName' in message_data
        assert 'groupName' in message_data
        assert 'accountId' in message_data
        assert 'timestamp' in message_data
        assert 'action' in message_data
        
        # Error message should not be present for success
        # (or if present, should be None/empty)
        if 'errorMessage' in message_data:
            assert message_data['errorMessage'] is None or message_data['errorMessage'] == ''
    
    @given(
        application_name=application_names,
        group_name=group_names,
        account_id=account_ids,
        timestamp=timestamps,
        action=actions,
        error_message=st.text(min_size=1, max_size=500)
    )
    @settings(max_examples=100)
    def test_message_format_for_failed_status(
        self,
        application_name,
        group_name,
        account_id,
        timestamp,
        action,
        error_message
    ):
        """
        **Property 6: Complete notification message format**
        
        For any failed notification (status=FAILED), the message should
        include all required fields and include an error message.
        """
        # Build notification message with FAILED status
        message = build_notification_message(
            application_name=application_name,
            group_name=group_name,
            account_id=account_id,
            timestamp=timestamp,
            action=action,
            status='FAILED',
            error_message=error_message
        )
        
        # Parse message
        message_data = json.loads(message)
        
        # Verify status is FAILED
        assert message_data['status'] == 'FAILED'
        
        # Verify all required fields are present
        assert 'applicationName' in message_data
        assert 'groupName' in message_data
        assert 'accountId' in message_data
        assert 'timestamp' in message_data
        assert 'action' in message_data
        
        # Error message should be present for failures
        assert 'errorMessage' in message_data
        assert message_data['errorMessage'] == error_message
    
    @given(
        action=actions,
        status=statuses
    )
    @settings(max_examples=100)
    def test_subject_line_format(self, action, status):
        """
        **Property 6: Complete notification message format**
        
        For any action and status combination, the subject line should
        be formatted correctly based on the action and status.
        """
        # Build subject line
        subject = build_subject_line(action=action, status=status)
        
        # Verify subject is not empty
        assert len(subject) > 0
        
        # Verify subject contains [Identity Center] prefix
        assert '[Identity Center]' in subject
        
        # Verify subject reflects status
        if status == 'FAILED':
            assert 'ERROR' in subject or 'Failed' in subject
        
        # Verify subject reflects action (for non-failed status)
        if status != 'FAILED':
            if action == 'DELETED':
                assert 'DELETED' in subject
            elif action == 'NOTIFICATION_ONLY':
                assert 'NOTIFICATION_ONLY' in subject
    
    @given(
        application_name=application_names,
        group_name=group_names,
        account_id=account_ids,
        timestamp=timestamps,
        action=actions,
        status=statuses,
        application_arn=st.text(min_size=20, max_size=200),
        principal_id=st.text(min_size=10, max_size=100)
    )
    @settings(max_examples=100)
    def test_message_includes_optional_fields_when_provided(
        self,
        application_name,
        group_name,
        account_id,
        timestamp,
        action,
        status,
        application_arn,
        principal_id
    ):
        """
        **Property 6: Complete notification message format**
        
        For any notification with optional fields provided (application ARN,
        principal ID), the message should include those fields.
        """
        # Build notification message with optional fields
        message = build_notification_message(
            application_name=application_name,
            group_name=group_name,
            account_id=account_id,
            timestamp=timestamp,
            action=action,
            status=status,
            application_arn=application_arn,
            principal_id=principal_id
        )
        
        # Parse message
        message_data = json.loads(message)
        
        # Verify optional fields are present
        assert 'applicationArn' in message_data
        assert 'groupDigest' in message_data
        assert 'groupId' not in message_data
        
        # Verify optional field values
        assert message_data['applicationArn'] == application_arn
        # Digest, not the raw principal ID -- and the raw value must be absent from
        # the whole message, since this is published to SNS and reaches every
        # subscriber.
        assert message_data['groupDigest'] == principal_digest(principal_id)
        # "the raw ID appears nowhere in the payload" is asserted in
        # TestNotificationFormatting.test_optional_fields_included_when_provided,
        # against a realistic UUID. It cannot be stated here: hypothesis generates
        # principal_id and account_id from overlapping alphabets and will produce
        # runs where they are equal, so the value is genuinely present in the
        # message as the account ID and the assertion would fail on a coincidence
        # rather than a leak. The two assertions above pin the behaviour of this
        # function -- the key is gone and the digest is correct.



class TestNotificationFormatting:
    """Unit tests for notification formatting functions."""
    
    def test_success_notification_format(self):
        """
        Test that success notifications are formatted correctly.
        
        Requirements: 4.2, 4.3
        """
        # Build success notification
        message = build_notification_message(
            application_name='TestApp',
            group_name='TestGroup',
            account_id='123456789012',
            timestamp='2025-12-16T10:30:00Z',
            action='DELETED',
            status='SUCCESS'
        )
        
        # Parse message
        message_data = json.loads(message)
        
        # Verify all required fields
        assert message_data['applicationName'] == 'TestApp'
        assert message_data['groupName'] == 'TestGroup'
        assert message_data['accountId'] == '123456789012'
        assert message_data['timestamp'] == '2025-12-16T10:30:00Z'
        assert message_data['action'] == 'DELETED'
        assert message_data['status'] == 'SUCCESS'
        assert message_data['eventType'] == 'NON_COMPLIANT_ASSIGNMENT'
        
        # Error message should not be present
        assert 'errorMessage' not in message_data or message_data.get('errorMessage') is None
    
    def test_failure_notification_format(self):
        """
        Test that failure notifications are formatted correctly with error message.
        
        Requirements: 4.2, 4.3
        """
        # Build failure notification
        error_msg = 'Access denied to delete assignment'
        message = build_notification_message(
            application_name='TestApp',
            group_name='TestGroup',
            account_id='123456789012',
            timestamp='2025-12-16T10:30:00Z',
            action='DELETED',
            status='FAILED',
            error_message=error_msg
        )
        
        # Parse message
        message_data = json.loads(message)
        
        # Verify all required fields
        assert message_data['applicationName'] == 'TestApp'
        assert message_data['groupName'] == 'TestGroup'
        assert message_data['accountId'] == '123456789012'
        assert message_data['timestamp'] == '2025-12-16T10:30:00Z'
        assert message_data['action'] == 'DELETED'
        assert message_data['status'] == 'FAILED'
        assert message_data['eventType'] == 'NON_COMPLIANT_ASSIGNMENT'
        
        # Error message should be present
        assert 'errorMessage' in message_data
        assert message_data['errorMessage'] == error_msg
    
    def test_all_required_fields_present(self):
        """
        Test that all required fields are present in notification message.
        
        Requirements: 4.2, 4.3
        """
        # Build notification
        message = build_notification_message(
            application_name='TestApp',
            group_name='TestGroup',
            account_id='123456789012',
            timestamp='2025-12-16T10:30:00Z',
            action='NOTIFICATION_ONLY',
            status='SUCCESS'
        )
        
        # Parse message
        message_data = json.loads(message)
        
        # Check all required fields
        required_fields = [
            'timestamp',
            'eventType',
            'accountId',
            'applicationName',
            'groupName',
            'action',
            'status'
        ]
        
        for field in required_fields:
            assert field in message_data, f"Required field '{field}' is missing"
    
    def test_subject_line_for_deleted_success(self):
        """
        Test subject line format for successful deletion.
        
        Requirements: 4.2, 4.3
        """
        subject = build_subject_line(action='DELETED', status='SUCCESS')
        
        assert '[Identity Center]' in subject
        assert 'DELETED' in subject
        assert 'ERROR' not in subject
    
    def test_subject_line_for_notification_only_success(self):
        """
        Test subject line format for notification-only success.
        
        Requirements: 4.2, 4.3
        """
        subject = build_subject_line(action='NOTIFICATION_ONLY', status='SUCCESS')
        
        assert '[Identity Center]' in subject
        assert 'NOTIFICATION_ONLY' in subject
        assert 'ERROR' not in subject
    
    def test_subject_line_for_failure(self):
        """
        Test subject line format for failures.
        
        Requirements: 4.2, 4.3
        """
        subject = build_subject_line(action='DELETED', status='FAILED')
        
        assert '[Identity Center]' in subject
        assert 'ERROR' in subject or 'Failed' in subject
    
    def test_optional_fields_included_when_provided(self):
        """
        Test that optional fields are included when provided.
        
        Requirements: 4.2, 4.3
        """
        # Build notification with optional fields
        message = build_notification_message(
            application_name='TestApp',
            group_name='TestGroup',
            account_id='123456789012',
            timestamp='2025-12-16T10:30:00Z',
            action='DELETED',
            status='SUCCESS',
            application_arn='arn:aws:sso:::application/test-app',
            principal_id='f81d4fae-7dec-11d0-a765-00a0c91e6bf6'
        )
        
        # Parse message
        message_data = json.loads(message)
        
        # Verify optional fields are present
        assert 'applicationArn' in message_data
        assert message_data['applicationArn'] == 'arn:aws:sso:::application/test-app'
        
        assert 'groupDigest' in message_data
        assert 'groupId' not in message_data
        # Digest, not the raw principal ID -- and the raw value must be absent from
        # the whole message, since this is published to SNS and reaches every
        # subscriber.
        assert message_data['groupDigest'] == principal_digest('f81d4fae-7dec-11d0-a765-00a0c91e6bf6')
        assert 'f81d4fae-7dec-11d0-a765-00a0c91e6bf6' not in message
    
    def test_initiated_by_omits_the_caller_session_name(self):
        """
        The caller is published as role + digest, never as an ARN or principalId.

        user_identity comes from CloudTrail, where an IAM Identity Center session
        carries the operator's email as the session name -- in both 'arn'
        (".../AWSReservedSSO_AdminAccess_abc/someone@example.com") and 'principalId'
        ("AROAEXAMPLE:someone@example.com"). This message is published to SNS, so
        those fields would deliver the email to every subscriber. CloudTrail stays
        the authoritative, IAM-gated record of who made the call.

        The user_identity branch had no test at all, which is why removing the
        redaction did not fail anything.
        """
        caller_arn = (
            'arn:aws:sts::123456789012:assumed-role/'
            'AWSReservedSSO_AdministratorAccess_abc123/someone@example.com'
        )
        caller_principal_id = 'AROAEXAMPLEID:someone@example.com'

        message = build_notification_message(
            application_name='TestApp',
            group_name='TestGroup',
            account_id='123456789012',
            timestamp='2025-12-16T10:30:00Z',
            action='DELETED',
            status='SUCCESS',
            user_identity={
                'type': 'AssumedRole',
                'arn': caller_arn,
                'principalId': caller_principal_id,
                'accountId': '123456789012',
            },
        )
        message_data = json.loads(message)
        initiated_by = message_data['initiatedBy']

        # The access path is kept -- that is the auditable part.
        assert initiated_by['role'] == 'AWSReservedSSO_AdministratorAccess_abc123'
        assert initiated_by['type'] == 'AssumedRole'
        assert initiated_by['accountId'] == '123456789012'
        assert initiated_by['callerDigest'] == principal_digest(caller_principal_id)

        # The identity is not.
        assert 'arn' not in initiated_by
        assert 'principalId' not in initiated_by
        assert 'someone@example.com' not in message
        assert caller_arn not in message
        assert caller_principal_id not in message

    def test_optional_fields_omitted_when_not_provided(self):
        """
        Test that optional fields are omitted when not provided.
        
        Requirements: 4.2, 4.3
        """
        # Build notification without optional fields
        message = build_notification_message(
            application_name='TestApp',
            group_name='TestGroup',
            account_id='123456789012',
            timestamp='2025-12-16T10:30:00Z',
            action='DELETED',
            status='SUCCESS'
        )
        
        # Parse message
        message_data = json.loads(message)
        
        # Verify optional fields are not present
        assert 'applicationArn' not in message_data
        assert 'groupDigest' not in message_data
        assert 'groupId' not in message_data
        assert 'errorMessage' not in message_data
