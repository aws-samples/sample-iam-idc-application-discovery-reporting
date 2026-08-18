"""
Integration tests for Lambda handler.

These tests verify the end-to-end flow of the Lambda handler including:
- Compliant assignment flow (no remediation)
- Non-compliant assignment with notification only
- Non-compliant assignment with auto-deletion
- Error handling in handler
"""

import pytest
import json
import os
from unittest.mock import Mock, patch, MagicMock
from handler import lambda_handler


@pytest.fixture
def valid_event():
    """Create a valid EventBridge event for testing."""
    return {
        'version': '0',
        'id': 'test-event-id',
        'detail-type': 'AWS API Call via CloudTrail',
        'source': 'aws.sso',
        'account': '123456789012',
        'time': '2025-12-15T10:30:00Z',
        'region': 'us-east-1',
        'detail': {
            'eventVersion': '1.08',
            'eventID': 'abc-123',
            'eventName': 'CreateApplicationAssignment',
            'eventTime': '2025-12-15T10:30:00Z',
            'eventSource': 'sso.amazonaws.com',
            'requestParameters': {
                'ApplicationArn': 'arn:aws:sso:::application/ins-123/app-456',
                'PrincipalId': 'group-789',
                'PrincipalType': 'GROUP',
                'directoryId': 'd-1234567890'
            }
        }
    }


@pytest.fixture
def lambda_context():
    """Create a mock Lambda context."""
    context = Mock()
    context.aws_request_id = 'test-request-id'
    context.function_name = 'test-function'
    context.memory_limit_in_mb = 256
    context.invoked_function_arn = 'arn:aws:lambda:us-east-1:123456789012:function:test'
    return context


@pytest.fixture
def mock_config():
    """Set up mock configuration environment variables."""
    os.environ['ENABLE_AUTO_DELETION'] = 'false'
    os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:test-topic'
    yield
    # Cleanup
    if 'ENABLE_AUTO_DELETION' in os.environ:
        del os.environ['ENABLE_AUTO_DELETION']
    if 'SNS_TOPIC_ARN' in os.environ:
        del os.environ['SNS_TOPIC_ARN']


def test_compliant_assignment_no_remediation(valid_event, lambda_context, mock_config):
    """
    Test compliant assignment flow where no remediation is needed.
    
    When group name is found in application name, the handler should:
    - Parse the event successfully
    - Validate the assignment as compliant
    - Not trigger any remediation
    - Not send any notifications
    - Return success status
    
    Validates: Requirements 1.1, 1.2, 2.3, 2.4
    """
    with patch('handler.IdentityCenterClient') as mock_ic_client_class, \
         patch('handler.IdentityStoreClient') as mock_is_client_class, \
         patch('handler.SNSClient') as mock_sns_client_class:
        
        # Mock Identity Center client to return compliant names
        mock_ic_client = Mock()
        mock_ic_client.list_applications_for_instance.return_value = [
            {
                'ApplicationArn': 'arn:aws:sso:::application/ins-123/app-456',
                'Name': 'MyApp-Developers-Production'
            }
        ]
        mock_ic_client_class.return_value = mock_ic_client
        
        # Mock Identity Store client to return group name
        mock_is_client = Mock()
        mock_is_client.describe_group.return_value = {
            'DisplayName': 'Developers'
        }
        mock_is_client_class.return_value = mock_is_client
        
        # Mock SNS client (should not be called for compliant assignments)
        mock_sns_client = Mock()
        mock_sns_client_class.return_value = mock_sns_client
        
        # Execute handler
        result = lambda_handler(valid_event, lambda_context)
        
        # Verify result
        assert result['statusCode'] == 200
        assert result['action'] == 'NONE'
        assert 'compliant' in result['body'].lower()
        
        # Verify Identity Center client was called to get application name
        mock_ic_client.list_applications_for_instance.assert_called_once()
        
        # Verify SNS client was NOT called (no notification for compliant assignments)
        mock_sns_client.publish_message.assert_not_called()
        
        # Verify deletion was NOT attempted
        mock_ic_client.delete_application_assignment.assert_not_called()


def test_user_assignment_exempt_from_validation(valid_event, lambda_context, mock_config):
    """
    USER principals are exempt from compliance validation.

    The naming convention binds GROUP names to application names; a user's
    display name is essentially never a substring of the application name, so
    validating users would flag (and in auto-remediation mode delete) every
    direct user assignment.
    """
    valid_event['detail']['requestParameters']['PrincipalType'] = 'USER'
    valid_event['detail']['requestParameters']['PrincipalId'] = 'user-123'

    with patch('handler.IdentityCenterClient') as mock_ic_client_class, \
         patch('handler.IdentityStoreClient') as mock_is_client_class, \
         patch('handler.SNSClient') as mock_sns_client_class:

        mock_ic_client = Mock()
        mock_ic_client.list_applications_for_instance.return_value = [
            {
                'ApplicationArn': 'arn:aws:sso:::application/ins-123/app-456',
                'Name': 'MyApp-Developers-Production'
            }
        ]
        mock_ic_client_class.return_value = mock_ic_client

        mock_is_client = Mock()
        # Display name deliberately NOT a substring of the application name
        mock_is_client.describe_user.return_value = {
            'DisplayName': 'Jane Smith'
        }
        mock_is_client_class.return_value = mock_is_client

        mock_sns_client = Mock()
        mock_sns_client_class.return_value = mock_sns_client

        result = lambda_handler(valid_event, lambda_context)

        assert result['statusCode'] == 200
        assert result['action'] == 'USER_EXEMPT'

        # No notification and no deletion for exempt user assignments
        mock_sns_client.publish_message.assert_not_called()
        mock_ic_client.delete_application_assignment.assert_not_called()


def test_non_compliant_notification_only(valid_event, lambda_context, mock_config):
    """
    Test non-compliant assignment with notification only (auto-deletion disabled).
    
    When group name is NOT found in application name and auto-deletion is disabled:
    - Parse the event successfully
    - Validate the assignment as non-compliant
    - Determine action as NOTIFICATION_ONLY
    - Send SNS notification
    - Not attempt deletion
    - Return success status
    
    Validates: Requirements 2.3, 2.4, 2.5, 3.2, 3.3, 4.1, 5.1
    """
    with patch('handler.IdentityCenterClient') as mock_ic_client_class, \
         patch('handler.IdentityStoreClient') as mock_is_client_class, \
         patch('handler.SNSClient') as mock_sns_client_class:
        
        # Mock Identity Center client to return non-compliant names
        mock_ic_client = Mock()
        mock_ic_client.list_applications_for_instance.return_value = [
            {
                'ApplicationArn': 'arn:aws:sso:::application/ins-123/app-456',
                'Name': 'MyApp-Production'
            }
        ]
        mock_ic_client_class.return_value = mock_ic_client
        
        # Mock Identity Store client to return group name
        mock_is_client = Mock()
        mock_is_client.describe_group.return_value = {
            'DisplayName': 'Developers'
        }
        mock_is_client_class.return_value = mock_is_client
        
        # Mock SNS client
        mock_sns_client = Mock()
        mock_sns_client.publish_message.return_value = {'MessageId': 'test-msg-id'}
        mock_sns_client_class.return_value = mock_sns_client
        
        # Execute handler
        result = lambda_handler(valid_event, lambda_context)
        
        # Verify result
        assert result['statusCode'] == 200
        assert result['action'] == 'NOTIFICATION_ONLY'
        assert result['status'] == 'SUCCESS'
        
        # Verify Identity Center client was called to get application name
        mock_ic_client.list_applications_for_instance.assert_called_once()
        
        # Verify SNS notification was sent
        mock_sns_client.publish_message.assert_called_once()
        call_args = mock_sns_client.publish_message.call_args
        
        # Verify notification contains required fields
        subject = call_args[1]['subject']
        message = call_args[1]['message']
        message_data = json.loads(message)
        
        assert 'NOTIFICATION_ONLY' in subject
        assert message_data['action'] == 'NOTIFICATION_ONLY'
        assert message_data['status'] == 'SUCCESS'
        assert message_data['applicationName'] == 'MyApp-Production'
        assert message_data['groupName'] == 'Developers'
        assert message_data['accountId'] == '123456789012'
        
        # Verify deletion was NOT attempted
        mock_ic_client.delete_application_assignment.assert_not_called()


def test_non_compliant_with_auto_deletion(valid_event, lambda_context):
    """
    Test non-compliant assignment with auto-deletion enabled.
    
    When group name is NOT found in application name and auto-deletion is enabled:
    - Parse the event successfully
    - Validate the assignment as non-compliant
    - Determine action as DELETED
    - Attempt to delete the assignment
    - Send SNS notification with deletion status
    - Return success status
    
    Validates: Requirements 2.5, 3.5, 5.1
    """
    # Set auto-deletion to true
    os.environ['ENABLE_AUTO_DELETION'] = 'true'
    os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:test-topic'
    
    try:
        with patch('handler.IdentityCenterClient') as mock_ic_client_class, \
             patch('handler.IdentityStoreClient') as mock_is_client_class, \
             patch('handler.SNSClient') as mock_sns_client_class:
            
            # Mock Identity Center client. get_application_name resolves via
            # list_applications_for_instance + ARN match, so the resolved name
            # must be returned there (not just describe_application) for the
            # fail-closed guard to see a resolved name.
            mock_ic_client = Mock()
            mock_ic_client.list_applications_for_instance.return_value = [
                {'ApplicationArn': 'arn:aws:sso:::application/ins-123/app-456',
                 'Name': 'MyApp-Production'}
            ]
            mock_ic_client.delete_application_assignment.return_value = {}
            mock_ic_client_class.return_value = mock_ic_client

            # Mock Identity Store client to return group name
            mock_is_client = Mock()
            mock_is_client.describe_group.return_value = {
                'DisplayName': 'Developers'
            }
            mock_is_client_class.return_value = mock_is_client

            # Mock SNS client
            mock_sns_client = Mock()
            mock_sns_client.publish_message.return_value = {'MessageId': 'test-msg-id'}
            mock_sns_client_class.return_value = mock_sns_client

            # Execute handler
            result = lambda_handler(valid_event, lambda_context)

            # Verify result
            assert result['statusCode'] == 200
            assert result['action'] == 'DELETED'
            assert result['status'] == 'SUCCESS'
            
            # Verify deletion was attempted
            mock_ic_client.delete_application_assignment.assert_called_once_with(
                application_arn='arn:aws:sso:::application/ins-123/app-456',
                principal_id='group-789',
                principal_type='GROUP'
            )
            
            # Verify SNS notification was sent
            mock_sns_client.publish_message.assert_called_once()
            call_args = mock_sns_client.publish_message.call_args
            
            # Verify notification contains deletion status
            message = call_args[1]['message']
            message_data = json.loads(message)
            
            assert message_data['action'] == 'DELETED'
            assert message_data['status'] == 'SUCCESS'
    
    finally:
        # Cleanup
        if 'ENABLE_AUTO_DELETION' in os.environ:
            del os.environ['ENABLE_AUTO_DELETION']
        if 'SNS_TOPIC_ARN' in os.environ:
            del os.environ['SNS_TOPIC_ARN']


def test_malformed_event_handling(lambda_context, mock_config):
    """
    Test error handling for malformed events.
    
    When event is missing required fields:
    - Attempt to parse the event
    - Catch parsing error
    - Send error notification
    - Return error status without attempting remediation
    
    Validates: Requirements 9.2
    """
    # Create malformed event (missing requestParameters)
    malformed_event = {
        'version': '0',
        'id': 'test-event-id',
        'source': 'aws.sso',
        'detail-type': 'AWS API Call via CloudTrail',
        'account': '123456789012',
        'detail': {
            'eventName': 'CreateApplicationAssignment'
            # Missing requestParameters
        }
    }
    
    with patch('handler.SNSClient') as mock_sns_client_class:
        # Mock SNS client
        mock_sns_client = Mock()
        mock_sns_client.publish_message.return_value = {'MessageId': 'test-msg-id'}
        mock_sns_client_class.return_value = mock_sns_client
        
        # Execute handler — the handler now RE-RAISES after sending the error
        # notification so the async invocation fails and the malformed (poison)
        # event is captured by the SQS dead-letter queue.
        with pytest.raises(Exception):
            lambda_handler(malformed_event, lambda_context)

        # Verify error notification was still sent before re-raising
        mock_sns_client.publish_message.assert_called_once()
        call_args = mock_sns_client.publish_message.call_args
        
        # Verify error notification format
        subject = call_args[1]['subject']
        message = call_args[1]['message']
        message_data = json.loads(message)
        
        assert 'PARSING' in subject or 'Error' in subject
        assert message_data['eventType'] == 'ERROR'
        assert message_data['errorCategory'] == 'PARSING'


def test_api_error_handling(valid_event, lambda_context, mock_config):
    """
    Test error handling when Identity Center API fails during application lookup.
    
    When API call fails to get application name:
    - Parse event successfully
    - Attempt to get application name
    - Handle API error gracefully by using ARN as fallback
    - Continue processing with ARN as application name
    - Send notification (since ARN won't match group name)
    
    Validates: Requirements 9.4, 9.5
    """
    with patch('handler.IdentityCenterClient') as mock_ic_client_class, \
         patch('handler.IdentityStoreClient') as mock_is_client_class, \
         patch('handler.SNSClient') as mock_sns_client_class:
        
        # Mock Identity Center client to raise error on describe_application
        mock_ic_client = Mock()
        mock_ic_client.describe_application.side_effect = Exception('API Error')
        mock_ic_client_class.return_value = mock_ic_client
        
        # Mock Identity Store client to return group name
        mock_is_client = Mock()
        mock_is_client.describe_group.return_value = {
            'DisplayName': 'Developers'
        }
        mock_is_client_class.return_value = mock_is_client
        
        # Mock SNS client
        mock_sns_client = Mock()
        mock_sns_client.publish_message.return_value = {'MessageId': 'test-msg-id'}
        mock_sns_client_class.return_value = mock_sns_client
        
        # Execute handler
        result = lambda_handler(valid_event, lambda_context)
        
        # Verify result - handler should gracefully handle the error and continue
        # It will use the ARN as the application name and proceed with validation
        assert result['statusCode'] == 200
        assert result['action'] == 'NOTIFICATION_ONLY'
        
        # Verify notification was sent (ARN won't match group name)
        mock_sns_client.publish_message.assert_called_once()
        call_args = mock_sns_client.publish_message.call_args
        
        # Verify notification contains the ARN as application name
        message = call_args[1]['message']
        message_data = json.loads(message)
        
        assert message_data['applicationName'] == 'arn:aws:sso:::application/ins-123/app-456'
        assert message_data['groupName'] == 'Developers'


def test_deletion_failure_notification(valid_event, lambda_context):
    """
    Test that deletion failures are properly notified.
    
    When deletion fails:
    - Attempt deletion
    - Capture deletion error
    - Send notification with FAILED status
    - Include error details in notification
    
    Validates: Requirements 5.3, 5.4, 5.5
    """
    # Set auto-deletion to true
    os.environ['ENABLE_AUTO_DELETION'] = 'true'
    os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:test-topic'
    
    try:
        with patch('handler.IdentityCenterClient') as mock_ic_client_class, \
             patch('handler.IdentityStoreClient') as mock_is_client_class, \
             patch('handler.SNSClient') as mock_sns_client_class, \
             patch('handler.delete_application_assignment') as mock_delete:
            
            # Mock Identity Center client (resolve app name via list+ARN match)
            mock_ic_client = Mock()
            mock_ic_client.list_applications_for_instance.return_value = [
                {'ApplicationArn': 'arn:aws:sso:::application/ins-123/app-456',
                 'Name': 'MyApp-Production'}
            ]
            mock_ic_client_class.return_value = mock_ic_client

            # Mock Identity Store client to return group name
            mock_is_client = Mock()
            mock_is_client.describe_group.return_value = {
                'DisplayName': 'Developers'
            }
            mock_is_client_class.return_value = mock_is_client

            # Mock deletion to fail
            from deletion import DeletionResult
            mock_delete.return_value = DeletionResult(
                success=False,
                application_arn='arn:aws:sso:::application/ins-123/app-456',
                principal_id='group-789',
                principal_type='GROUP',
                error_message='Access Denied',
                error_code='AccessDeniedException'
            )
            
            # Mock SNS client
            mock_sns_client = Mock()
            mock_sns_client.publish_message.return_value = {'MessageId': 'test-msg-id'}
            mock_sns_client_class.return_value = mock_sns_client
            
            # Execute handler
            result = lambda_handler(valid_event, lambda_context)
            
            # Verify result
            assert result['statusCode'] == 200
            assert result['action'] == 'DELETED'
            assert result['status'] == 'FAILED'
            
            # Verify SNS notification was sent with failure status
            mock_sns_client.publish_message.assert_called_once()
            call_args = mock_sns_client.publish_message.call_args
            
            # Verify notification contains error details
            message = call_args[1]['message']
            message_data = json.loads(message)
            
            assert message_data['action'] == 'DELETED'
            assert message_data['status'] == 'FAILED'
            assert message_data['errorMessage'] == 'Access Denied'
    
    finally:
        # Cleanup
        if 'ENABLE_AUTO_DELETION' in os.environ:
            del os.environ['ENABLE_AUTO_DELETION']
        if 'SNS_TOPIC_ARN' in os.environ:
            del os.environ['SNS_TOPIC_ARN']


def test_associate_profile_fails_closed_on_unresolved_application(lambda_context):
    """
    Regression (SA finding #8): when the application name for an
    AssociateProfile event cannot be resolved, the handler falls back to
    'Profile-<id>' — which is never a real application name, so the verdict is
    untrustworthy. Auto-deletion must be downgraded to notification.
    """
    os.environ['ENABLE_AUTO_DELETION'] = 'true'
    os.environ['SNS_TOPIC_ARN'] = 'arn:aws:sns:us-east-1:123456789012:test-topic'
    os.environ['IDENTITY_CENTER_INSTANCE_ARN'] = 'arn:aws:sso:::instance/ssoins-test'
    try:
        event = {
            'version': '0', 'id': 'test', 'detail-type': 'AWS API Call via CloudTrail',
            'source': 'aws.sso', 'account': '123456789012',
            'time': '2025-12-15T10:30:00Z', 'region': 'us-east-1',
            'detail': {
                'eventVersion': '1.08', 'eventID': 'x', 'eventName': 'AssociateProfile',
                'eventTime': '2025-12-15T10:30:00Z', 'eventSource': 'sso.amazonaws.com',
                'requestParameters': {
                    'profileId': 'pr-abc123', 'instanceId': 'ins-def456',
                    'directoryId': 'd-1234567890',
                    'ApplicationArn': 'arn:aws:sso:::application/ins-def456/app-x',
                    'PrincipalId': 'group-789', 'PrincipalType': 'GROUP'
                }
            }
        }

        with patch('handler.IdentityCenterClient') as mock_ic_class, \
             patch('handler.IdentityStoreClient') as mock_is_class, \
             patch('handler.SNSClient') as mock_sns_class:

            mock_ic = Mock()
            # Application resolution fails -> fallback name Profile-pr-abc123
            mock_ic.get_application_from_instance_and_profile.return_value = None
            mock_ic_class.return_value = mock_ic

            mock_is = Mock()
            mock_is.describe_group.return_value = {'DisplayName': 'Developers'}
            mock_is_class.return_value = mock_is

            mock_sns = Mock()
            mock_sns_class.return_value = mock_sns

            result = lambda_handler(event, lambda_context)

            assert result['statusCode'] == 200
            # The verdict is non-compliant (fallback name never matches), but
            # deletion must be downgraded because the name is unresolved.
            mock_ic.delete_application_assignment.assert_not_called()
    finally:
        for k in ('ENABLE_AUTO_DELETION', 'SNS_TOPIC_ARN', 'IDENTITY_CENTER_INSTANCE_ARN'):
            os.environ.pop(k, None)


def test_rejects_untrusted_invocation_source(valid_event, lambda_context, mock_config):
    """
    Regression (SA finding #6): events not originating from the aws.sso
    EventBridge source are rejected before any validation/remediation, so a
    crafted direct invocation cannot trigger assignment deletion.
    """
    valid_event['source'] = 'attacker.crafted'
    with patch('handler.IdentityCenterClient') as mock_ic_class, \
         patch('handler.IdentityStoreClient'), \
         patch('handler.SNSClient'):
        mock_ic = Mock()
        mock_ic_class.return_value = mock_ic
        result = lambda_handler(valid_event, lambda_context)
        assert result['statusCode'] == 403
        assert result['action'] == 'REJECTED'
        mock_ic.delete_application_assignment.assert_not_called()


@pytest.fixture
def assignment_config_event():
    """
    EventBridge event for PutApplicationAssignmentConfiguration.

    This event carries no principal -- its requestParameters are
    {applicationArn, assignmentRequired} -- so it cannot flow through the
    principal-based validation path.

    requestParameters shape confirmed against a real CloudTrail event captured
    from a live put-application-assignment-configuration call: the keys are
    emitted as lowerCamelCase ('applicationArn', 'assignmentRequired'), not the
    PascalCase used by the API parameters.
    """
    return {
        'version': '0',
        'id': 'test-event-id',
        'detail-type': 'AWS API Call via CloudTrail',
        'source': 'aws.sso',
        'account': '123456789012',
        'time': '2025-12-15T10:30:00Z',
        'region': 'us-east-1',
        'detail': {
            'eventVersion': '1.08',
            'eventID': 'abc-123',
            'eventName': 'PutApplicationAssignmentConfiguration',
            'eventTime': '2025-12-15T10:30:00Z',
            'eventSource': 'sso.amazonaws.com',
            'requestParameters': {
                'applicationArn': 'arn:aws:sso:::application/ins-123/app-456',
                'assignmentRequired': False
            }
        }
    }


def test_assignment_required_disabled_alerts(
    assignment_config_event, lambda_context, mock_config
):
    """
    assignmentRequired=false must raise a distinct alert.

    Setting assignmentRequired to false makes the application reachable by every
    user in the identity store without any application assignment existing,
    which bypasses assignment-level naming governance entirely. The handler must
    notify rather than fall through to the principal-based validation path.
    """
    with patch('handler.IdentityCenterClient') as mock_ic_client_class, \
         patch('handler.IdentityStoreClient') as mock_is_client_class, \
         patch('handler.SNSClient') as mock_sns_client_class:

        mock_ic_client = Mock()
        mock_ic_client.list_applications_for_instance.return_value = [
            {
                'ApplicationArn': 'arn:aws:sso:::application/ins-123/app-456',
                'Name': 'sagemaker_readonly'
            }
        ]
        mock_ic_client_class.return_value = mock_ic_client

        mock_is_client_class.return_value = Mock()
        mock_sns_client = Mock()
        mock_sns_client_class.return_value = mock_sns_client

        result = lambda_handler(assignment_config_event, lambda_context)

        assert result['statusCode'] == 200
        assert result['action'] == 'ASSIGNMENT_REQUIRED_DISABLED'

        # A notification must have been sent for the risky transition.
        assert mock_sns_client.publish_message.called, \
            "assignmentRequired=false must notify"


def test_assignment_required_enabled_is_audit_only(
    assignment_config_event, lambda_context, mock_config
):
    """
    assignmentRequired=true is the safe direction and is audit-only.

    Re-enabling assignment enforcement tightens posture, so it is recorded but
    must not be reported as the risky transition.
    """
    assignment_config_event['detail']['requestParameters']['assignmentRequired'] = True

    with patch('handler.IdentityCenterClient') as mock_ic_client_class, \
         patch('handler.IdentityStoreClient') as mock_is_client_class, \
         patch('handler.SNSClient') as mock_sns_client_class:

        mock_ic_client = Mock()
        mock_ic_client.list_applications_for_instance.return_value = [
            {
                'ApplicationArn': 'arn:aws:sso:::application/ins-123/app-456',
                'Name': 'sagemaker_readonly'
            }
        ]
        mock_ic_client_class.return_value = mock_ic_client
        mock_is_client_class.return_value = Mock()
        mock_sns_client_class.return_value = Mock()

        result = lambda_handler(assignment_config_event, lambda_context)

        assert result['statusCode'] == 200
        assert result['action'] == 'AUDIT_LOG'


def test_assignment_required_absent_is_not_treated_as_open(
    assignment_config_event, lambda_context, mock_config
):
    """
    A missing assignmentRequired field must not be inferred as "open".

    If CloudTrail did not record the field, treating absence as false would
    raise a false alarm on every such event.
    """
    del assignment_config_event['detail']['requestParameters']['assignmentRequired']

    with patch('handler.IdentityCenterClient') as mock_ic_client_class, \
         patch('handler.IdentityStoreClient') as mock_is_client_class, \
         patch('handler.SNSClient') as mock_sns_client_class:

        mock_ic_client = Mock()
        mock_ic_client.list_applications_for_instance.return_value = [
            {
                'ApplicationArn': 'arn:aws:sso:::application/ins-123/app-456',
                'Name': 'sagemaker_readonly'
            }
        ]
        mock_ic_client_class.return_value = mock_ic_client
        mock_is_client_class.return_value = Mock()
        mock_sns_client_class.return_value = Mock()

        result = lambda_handler(assignment_config_event, lambda_context)

        assert result['statusCode'] == 200
        assert result['action'] == 'AUDIT_LOG', \
            "absent assignmentRequired must not be reported as disabled"
