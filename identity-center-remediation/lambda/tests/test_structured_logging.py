"""
Property-based tests for structured logging module.

**Feature: identity-center-app-monitor, Property 10: Comprehensive structured logging**
**Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5**

Property: For any Lambda invocation, the system should produce JSON-formatted logs
containing event details, validation results, remediation actions, and any errors
with stack traces.
"""

import json
import io
import sys
from hypothesis import given, strategies as st, assume
from hypothesis.strategies import composite
import pytest
from structured_logging import (
    StructuredLogger,
    get_logger,
    log_lambda_invocation,
    log_event_parsing,
    log_validation_result,
    log_remediation_action,
    log_deletion_attempt,
    log_deletion_result,
    log_notification_sent,
    log_error,
    log_processing_complete
)
from validation import ValidationResult
from deletion import DeletionResult


# Strategy for generating valid event payloads
@composite
def event_payload(draw):
    """Generate random EventBridge event payloads."""
    account_id = draw(st.text(min_size=12, max_size=12, alphabet=st.characters(whitelist_categories=('Nd',))))
    region = draw(st.sampled_from(['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1']))
    event_name = draw(st.sampled_from(['CreateApplicationAssignment', 'DeleteApplicationAssignment']))
    
    return {
        "version": "0",
        "id": draw(st.uuids()).hex,
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.sso",
        "account": account_id,
        "time": "2025-12-15T10:30:00Z",
        "region": region,
        "detail": {
            "eventVersion": "1.08",
            "eventID": draw(st.uuids()).hex,
            "eventName": event_name,
            "eventTime": "2025-12-15T10:30:00Z",
            "eventSource": "sso.amazonaws.com",
            "requestParameters": {
                "ApplicationArn": f"arn:aws:sso:::application/ssoins-{draw(st.text(min_size=16, max_size=16, alphabet='0123456789abcdef'))}/apl-{draw(st.text(min_size=16, max_size=16, alphabet='0123456789abcdef'))}",
                "PrincipalId": str(draw(st.uuids())),
                "PrincipalType": draw(st.sampled_from(["USER", "GROUP"]))
            }
        }
    }


@composite
def validation_result_strategy(draw):
    """Generate random ValidationResult objects."""
    is_compliant = draw(st.booleans())
    app_name = draw(st.text(min_size=1, max_size=50))
    group_name = draw(st.text(min_size=1, max_size=50))
    reason = draw(st.text(min_size=0, max_size=100))
    
    return ValidationResult(
        is_compliant=is_compliant,
        application_name=app_name,
        group_name=group_name,
        reason=reason
    )


@composite
def deletion_result_strategy(draw):
    """Generate random DeletionResult objects."""
    success = draw(st.booleans())
    app_arn = f"arn:aws:sso:::application/ssoins-{draw(st.text(min_size=16, max_size=16, alphabet='0123456789abcdef'))}/apl-{draw(st.text(min_size=16, max_size=16, alphabet='0123456789abcdef'))}"
    principal_id = str(draw(st.uuids()))
    principal_type = draw(st.sampled_from(["USER", "GROUP"]))
    
    if success:
        return DeletionResult(
            success=True,
            application_arn=app_arn,
            principal_id=principal_id,
            principal_type=principal_type
        )
    else:
        error_code = draw(st.sampled_from([
            'AccessDeniedException',
            'ResourceNotFoundException',
            'ThrottlingException',
            'UnknownError'
        ]))
        error_message = draw(st.text(min_size=10, max_size=100))
        
        return DeletionResult(
            success=False,
            application_arn=app_arn,
            principal_id=principal_id,
            principal_type=principal_type,
            error_message=error_message,
            error_code=error_code
        )


def capture_log_output(func, *args, **kwargs):
    """
    Capture log output from a logging function.
    
    Returns:
        Tuple of (log_output_string, parsed_json_or_none)
    """
    # Reset the global logger to ensure fresh state
    import structured_logging
    structured_logging._logger = None
    
    # Capture stdout
    old_stdout = sys.stdout
    sys.stdout = captured_output = io.StringIO()
    
    try:
        # Call the logging function
        func(*args, **kwargs)
        
        # Flush any buffered output
        sys.stdout.flush()
        
        # Get the output
        output = captured_output.getvalue()
        
        # Try to parse as JSON
        if output.strip():
            try:
                # Handle multiple JSON objects on separate lines
                lines = output.strip().split('\n')
                if len(lines) == 1:
                    parsed = json.loads(lines[0])
                    return output, parsed
                else:
                    # Return the first JSON object
                    parsed = json.loads(lines[0])
                    return output, parsed
            except json.JSONDecodeError:
                return output, None
        
        return output, None
    finally:
        sys.stdout = old_stdout
        # Reset logger again
        structured_logging._logger = None


@given(event_payload())
def test_log_lambda_invocation_produces_valid_json(event):
    """
    Property: Lambda invocation logs should always be valid JSON.
    
    For any event payload, log_lambda_invocation should produce valid JSON
    containing event details.
    """
    output, parsed = capture_log_output(log_lambda_invocation, event)
    
    # Should produce output
    assert output.strip() != "", "Log output should not be empty"
    
    # Should be valid JSON
    assert parsed is not None, f"Log output should be valid JSON, got: {output}"
    
    # Should contain required fields
    assert "timestamp" in parsed, "Log should contain timestamp"
    assert "level" in parsed, "Log should contain level"
    assert "message" in parsed, "Log should contain message"
    assert "stage" in parsed, "Log should contain stage"
    
    # Should contain event details
    assert "accountId" in parsed, "Log should contain accountId"
    assert parsed["accountId"] == event.get("account", "")


@given(
    st.booleans(),
    st.one_of(
        st.none(),
        st.dictionaries(
            st.sampled_from(['application_arn', 'principal_id', 'principal_type', 'account_id']),
            st.text(min_size=1, max_size=100),
            min_size=1
        )
    ),
    st.one_of(st.none(), st.text(min_size=1, max_size=200))
)
def test_log_event_parsing_produces_valid_json(success, parsed_data, error):
    """
    Property: Event parsing logs should always be valid JSON.
    
    For any parsing result (success or failure), log_event_parsing should
    produce valid JSON containing the parsing outcome.
    """
    output, parsed = capture_log_output(log_event_parsing, success, parsed_data, error)
    
    # Should produce output
    assert output.strip() != "", "Log output should not be empty"
    
    # Should be valid JSON
    assert parsed is not None, f"Log output should be valid JSON, got: {output}"
    
    # Should contain required fields
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "message" in parsed
    assert "stage" in parsed
    assert "success" in parsed
    
    # Should match the success parameter
    assert parsed["success"] == success
    
    # If failed, should contain error
    if not success:
        assert "error" in parsed


@given(validation_result_strategy())
def test_log_validation_result_produces_valid_json(validation_result):
    """
    Property: Validation logs should always be valid JSON.
    
    For any validation result, log_validation_result should produce valid JSON
    containing the validation outcome and details.
    """
    output, parsed = capture_log_output(log_validation_result, validation_result)
    
    # Should produce output
    assert output.strip() != "", "Log output should not be empty"
    
    # Should be valid JSON
    assert parsed is not None, f"Log output should be valid JSON, got: {output}"
    
    # Should contain required fields
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "message" in parsed
    assert "stage" in parsed
    assert "isCompliant" in parsed
    assert "complianceStatus" in parsed
    assert "applicationName" in parsed
    assert "groupName" in parsed
    assert "matchFound" in parsed
    assert "complianceDetail" in parsed
    
    # Compliance status should be COMPLIANT or NON_COMPLIANT
    assert parsed["complianceStatus"] in ["COMPLIANT", "NON_COMPLIANT"]
    
    # Should match the validation result
    expected_status = "COMPLIANT" if validation_result.is_compliant else "NON_COMPLIANT"
    assert parsed["complianceStatus"] == expected_status
    assert parsed["isCompliant"] == validation_result.is_compliant
    assert parsed["matchFound"] == validation_result.is_compliant


@given(
    st.sampled_from(['NONE', 'NOTIFICATION_ONLY', 'DELETED']),
    st.booleans()
)
def test_log_remediation_action_produces_valid_json(action, enable_auto_deletion):
    """
    Property: Remediation action logs should always be valid JSON.
    
    For any remediation action, log_remediation_action should produce valid JSON
    containing the action details.
    """
    output, parsed = capture_log_output(
        log_remediation_action,
        action,
        enable_auto_deletion=enable_auto_deletion
    )
    
    # Should produce output
    assert output.strip() != "", "Log output should not be empty"
    
    # Should be valid JSON
    assert parsed is not None, f"Log output should be valid JSON, got: {output}"
    
    # Should contain required fields
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "message" in parsed
    assert "stage" in parsed
    assert "action" in parsed
    assert "autoDeleteEnabled" in parsed
    
    # Should match the parameters
    assert parsed["action"] == action
    assert parsed["autoDeleteEnabled"] == enable_auto_deletion


@given(deletion_result_strategy())
def test_log_deletion_result_produces_valid_json(deletion_result):
    """
    Property: Deletion result logs should always be valid JSON.
    
    For any deletion result, log_deletion_result should produce valid JSON
    containing the deletion outcome and any error details.
    """
    output, parsed = capture_log_output(log_deletion_result, deletion_result)
    
    # Should produce output
    assert output.strip() != "", "Log output should not be empty"
    
    # Should be valid JSON
    assert parsed is not None, f"Log output should be valid JSON, got: {output}"
    
    # Should contain required fields
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "message" in parsed
    assert "stage" in parsed
    assert "success" in parsed
    assert "applicationArn" in parsed
    assert "principalId" in parsed
    
    # Should match the deletion result
    assert parsed["success"] == deletion_result.success
    
    # If failed, should contain error details
    if not deletion_result.success:
        assert "errorCode" in parsed
        assert "errorMessage" in parsed


@given(
    st.booleans(),
    st.sampled_from(['DELETED', 'NOTIFICATION_ONLY']),
    st.sampled_from(['SUCCESS', 'FAILED']),
    st.text(min_size=1, max_size=50),
    st.text(min_size=1, max_size=50),
    st.one_of(st.none(), st.text(min_size=1, max_size=200))
)
def test_log_notification_sent_produces_valid_json(
    success, action, status, app_name, group_name, error
):
    """
    Property: Notification logs should always be valid JSON.
    
    For any notification result, log_notification_sent should produce valid JSON
    containing the notification outcome.
    """
    output, parsed = capture_log_output(
        log_notification_sent,
        success,
        action,
        status,
        app_name,
        group_name,
        error
    )
    
    # Should produce output
    assert output.strip() != "", "Log output should not be empty"
    
    # Should be valid JSON
    assert parsed is not None, f"Log output should be valid JSON, got: {output}"
    
    # Should contain required fields
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "message" in parsed
    assert "stage" in parsed
    assert "success" in parsed
    assert "action" in parsed
    assert "status" in parsed
    
    # Should match the parameters
    assert parsed["success"] == success
    assert parsed["action"] == action
    assert parsed["status"] == status


@given(
    st.text(min_size=1, max_size=200),
    st.text(min_size=1, max_size=50),
    st.text(min_size=1, max_size=50),
    st.one_of(st.none(), st.text(min_size=10, max_size=500))
)
def test_log_error_produces_valid_json_with_stack_trace(
    error_message, error_type, stage, stack_trace
):
    """
    Property: Error logs should always be valid JSON with error details.
    
    For any error, log_error should produce valid JSON containing the error
    message, type, stage, and optional stack trace.
    """
    output, parsed = capture_log_output(
        log_error,
        error_message,
        error_type,
        stage,
        stack_trace
    )
    
    # Should produce output
    assert output.strip() != "", "Log output should not be empty"
    
    # Should be valid JSON
    assert parsed is not None, f"Log output should be valid JSON, got: {output}"
    
    # Should contain required fields
    assert "timestamp" in parsed
    assert "level" in parsed
    assert parsed["level"] == "ERROR", "Error logs should have ERROR level"
    assert "message" in parsed
    assert "stage" in parsed
    assert "errorType" in parsed
    assert "errorMessage" in parsed
    
    # Should match the parameters
    assert parsed["errorType"] == error_type
    assert parsed["errorMessage"] == error_message
    assert parsed["stage"] == stage
    
    # If stack trace provided, should be included
    if stack_trace:
        assert "stackTrace" in parsed
        assert parsed["stackTrace"] == stack_trace


@given(
    st.booleans(),
    st.sampled_from(['NONE', 'NOTIFICATION_ONLY', 'DELETED']),
    st.one_of(st.none(), st.floats(min_value=0, max_value=60000))
)
def test_log_processing_complete_produces_valid_json(success, action_taken, duration_ms):
    """
    Property: Processing completion logs should always be valid JSON.
    
    For any processing outcome, log_processing_complete should produce valid JSON
    containing the completion status and action taken.
    """
    output, parsed = capture_log_output(
        log_processing_complete,
        success,
        action_taken,
        duration_ms
    )
    
    # Should produce output
    assert output.strip() != "", "Log output should not be empty"
    
    # Should be valid JSON
    assert parsed is not None, f"Log output should be valid JSON, got: {output}"
    
    # Should contain required fields
    assert "timestamp" in parsed
    assert "level" in parsed
    assert "message" in parsed
    assert "stage" in parsed
    assert "success" in parsed
    assert "actionTaken" in parsed
    
    # Should match the parameters
    assert parsed["success"] == success
    assert parsed["actionTaken"] == action_taken
    
    # If duration provided, should be included
    if duration_ms is not None:
        assert "durationMs" in parsed


@given(event_payload(), validation_result_strategy(), deletion_result_strategy())
def test_comprehensive_logging_workflow_produces_valid_json(event, validation_result, deletion_result):
    """
    Property: Complete logging workflow should produce valid JSON at each stage.
    
    For any complete processing workflow (invocation -> parsing -> validation ->
    deletion -> notification -> completion), all logs should be valid JSON.
    """
    # Capture all logs
    logs = []
    
    # 1. Log invocation
    output, parsed = capture_log_output(log_lambda_invocation, event)
    assert parsed is not None, "Invocation log should be valid JSON"
    logs.append(parsed)
    
    # 2. Log parsing
    parsed_data = {
        'application_arn': event['detail']['requestParameters']['ApplicationArn'],
        'principal_id': event['detail']['requestParameters']['PrincipalId'],
        'principal_type': event['detail']['requestParameters']['PrincipalType'],
        'account_id': event['account']
    }
    output, parsed = capture_log_output(log_event_parsing, True, parsed_data, None)
    assert parsed is not None, "Parsing log should be valid JSON"
    logs.append(parsed)
    
    # 3. Log validation
    output, parsed = capture_log_output(log_validation_result, validation_result)
    assert parsed is not None, "Validation log should be valid JSON"
    logs.append(parsed)
    
    # 4. Log remediation action
    action = 'DELETED' if not validation_result.is_compliant else 'NONE'
    output, parsed = capture_log_output(log_remediation_action, action, validation_result, True)
    assert parsed is not None, "Remediation log should be valid JSON"
    logs.append(parsed)
    
    # 5. Log deletion result (if applicable)
    if action == 'DELETED':
        output, parsed = capture_log_output(log_deletion_result, deletion_result)
        assert parsed is not None, "Deletion log should be valid JSON"
        logs.append(parsed)
    
    # 6. Log notification
    notification_status = 'SUCCESS' if deletion_result.success else 'FAILED'
    output, parsed = capture_log_output(
        log_notification_sent,
        True,
        action,
        notification_status,
        validation_result.application_name,
        validation_result.group_name,
        None
    )
    assert parsed is not None, "Notification log should be valid JSON"
    logs.append(parsed)
    
    # 7. Log completion
    output, parsed = capture_log_output(log_processing_complete, True, action, 1000.0)
    assert parsed is not None, "Completion log should be valid JSON"
    logs.append(parsed)
    
    # All logs should have required fields
    for log in logs:
        assert "timestamp" in log, "All logs should have timestamp"
        assert "level" in log, "All logs should have level"
        assert "message" in log, "All logs should have message"
        assert "stage" in log, "All logs should have stage"
    
    # Stages should be in expected order
    expected_stages = ['invocation', 'event_parsing', 'validation', 'remediation_decision']
    if action == 'DELETED':
        expected_stages.append('deletion')
    expected_stages.extend(['notification', 'completion'])
    
    actual_stages = [log['stage'] for log in logs]
    assert actual_stages == expected_stages, f"Stages should be in order: {expected_stages}, got: {actual_stages}"
