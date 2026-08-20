"""
Property-based tests for error handling module.

Feature: identity-center-app-monitor
"""

import pytest
import json
from hypothesis import given, strategies as st, assume
from error_handler import (
    categorize_error,
    determine_severity,
    build_error_notification,
    format_error_notification_message,
    build_error_subject_line,
    handle_malformed_event,
    handle_global_exception,
    ErrorCategory,
    ErrorSeverity
)
from event_parser import EventParsingError, parse_event
from structured_logging import principal_digest
from botocore.exceptions import ClientError


# Strategies for generating malformed events
@st.composite
def malformed_event(draw):
    """
    Generate malformed CloudTrail events with missing or invalid fields.
    
    This strategy creates events that are missing required fields or have
    invalid structure to test error handling.
    """
    # Start with a base structure
    event = {
        'version': '0',
        'id': draw(st.uuids().map(str)),
        'detail-type': 'AWS API Call via CloudTrail',
        'source': 'aws.sso'
    }
    
    # Randomly include or exclude required fields
    if draw(st.booleans()):
        event['account'] = draw(st.text(min_size=1, max_size=20))
    
    if draw(st.booleans()):
        event['time'] = draw(st.text(min_size=1, max_size=50))
    
    if draw(st.booleans()):
        event['region'] = draw(st.text(min_size=1, max_size=20))
    
    # Create detail with potentially missing fields
    detail = {}
    
    if draw(st.booleans()):
        detail['eventName'] = draw(st.text(min_size=1, max_size=50))
    
    if draw(st.booleans()):
        detail['eventSource'] = draw(st.text(min_size=1, max_size=50))
    
    # Create requestParameters with potentially missing fields
    if draw(st.booleans()):
        request_params = {}
        
        if draw(st.booleans()):
            request_params['ApplicationArn'] = draw(st.text(min_size=1, max_size=100))
        
        if draw(st.booleans()):
            request_params['PrincipalId'] = draw(st.text(min_size=1, max_size=50))
        
        if draw(st.booleans()):
            request_params['PrincipalType'] = draw(st.sampled_from(['USER', 'GROUP', 'INVALID']))
        
        detail['requestParameters'] = request_params
    
    event['detail'] = detail
    
    return event


# **Feature: identity-center-app-monitor, Property 12: Graceful handling of malformed events**
# **Validates: Requirements 9.2**
@given(event=malformed_event())
def test_property_graceful_malformed_event_handling(event):
    """
    Property 12: Graceful handling of malformed events
    
    For any event payload that cannot be parsed or is missing required fields,
    the system should log the error, send a notification, and complete without
    attempting remediation.
    
    Validates: Requirements 9.2
    """
    # Attempt to parse the event - this should raise an exception for malformed events
    parsing_exception = None
    
    try:
        parsed = parse_event(event)
        # If parsing succeeds, this event is actually valid, skip this test case
        assume(False)
    except EventParsingError as e:
        parsing_exception = e
    except Exception as e:
        # Catch any other exception (but not hypothesis internal exceptions)
        from hypothesis.errors import UnsatisfiedAssumption
        if isinstance(e, UnsatisfiedAssumption):
            raise  # Re-raise hypothesis exceptions
        parsing_exception = e
    
    # If we get here, we should have a parsing exception
    assert parsing_exception is not None, "Malformed event should raise an exception"
    
    # Handle the malformed event
    result = handle_malformed_event(event, parsing_exception)
    
    # Verify the result structure
    assert 'error' in result
    assert 'shouldNotify' in result
    assert 'shouldRemediate' in result
    
    # Verify notification should be sent
    assert result['shouldNotify'] is True
    
    # Verify remediation should NOT be attempted
    assert result['shouldRemediate'] is False
    
    # Verify error notification contains required fields
    error = result['error']
    assert 'timestamp' in error
    assert 'eventType' in error
    assert error['eventType'] == 'ERROR'
    assert 'severity' in error
    assert 'errorCategory' in error
    assert 'errorMessage' in error
    # The stack trace must NOT reach the notification: this payload is published
    # to SNS, and a traceback carries whatever the exception message interpolated,
    # which in this codebase is routinely a principal ID. It is logged to
    # CloudWatch instead, where IAM controls who can read it.
    assert 'stackTrace' not in error
    assert 'context' in error
    
    # Verify error is categorized as PARSING (EventParsingError should always be PARSING)
    # The categorize_error function should recognize EventParsingError as PARSING
    category = categorize_error(parsing_exception)
    assert category == ErrorCategory.PARSING, f"Expected PARSING but got {category} for exception {type(parsing_exception).__name__}"
    assert error['errorCategory'] == ErrorCategory.PARSING.value


def test_categorize_parsing_error():
    """Test that EventParsingError is categorized as PARSING."""
    exception = EventParsingError("Missing field")
    category = categorize_error(exception)
    assert category == ErrorCategory.PARSING


def test_categorize_transient_error():
    """Test that throttling errors are categorized as TRANSIENT."""
    # Create a mock ClientError for throttling
    error_response = {
        'Error': {
            'Code': 'ThrottlingException',
            'Message': 'Rate exceeded'
        }
    }
    exception = ClientError(error_response, 'DescribeApplication')
    category = categorize_error(exception)
    assert category == ErrorCategory.TRANSIENT


def test_categorize_permanent_error():
    """Test that access denied errors are categorized as PERMANENT."""
    error_response = {
        'Error': {
            'Code': 'AccessDeniedException',
            'Message': 'Access denied'
        }
    }
    exception = ClientError(error_response, 'DeleteApplicationAssignment')
    category = categorize_error(exception)
    assert category == ErrorCategory.PERMANENT


def test_categorize_unexpected_error():
    """Test that unknown errors are categorized as UNEXPECTED."""
    exception = RuntimeError("Something went wrong")
    category = categorize_error(exception)
    assert category == ErrorCategory.UNEXPECTED


def test_determine_severity():
    """Test severity determination for different error categories."""
    assert determine_severity(ErrorCategory.TRANSIENT) == ErrorSeverity.MEDIUM
    assert determine_severity(ErrorCategory.PERMANENT) == ErrorSeverity.HIGH
    assert determine_severity(ErrorCategory.PARSING) == ErrorSeverity.MEDIUM
    assert determine_severity(ErrorCategory.UNEXPECTED) == ErrorSeverity.HIGH


def test_build_error_notification():
    """Test building error notification structure."""
    exception = EventParsingError("Missing ApplicationArn")
    context = {
        'eventId': 'test-123',
        'accountId': '123456789012'
    }
    
    notification = build_error_notification(exception, context)
    
    # Verify structure
    assert notification['eventType'] == 'ERROR'
    assert notification['errorCategory'] == ErrorCategory.PARSING.value
    assert notification['severity'] == ErrorSeverity.MEDIUM.value
    assert 'Missing ApplicationArn' in notification['errorMessage']
    assert notification['context'] == context
    assert 'timestamp' in notification
    # The stack trace must NOT reach the notification: this payload is published
    # to SNS, and a traceback carries whatever the exception message interpolated,
    # which in this codebase is routinely a principal ID. It is logged to
    # CloudWatch instead, where IAM controls who can read it.
    assert 'stackTrace' not in notification


def test_format_error_notification_message():
    """Test formatting error notification as JSON."""
    notification = {
        'eventType': 'ERROR',
        'errorMessage': 'Test error'
    }
    
    message = format_error_notification_message(notification)
    
    # Verify it's valid JSON
    parsed = json.loads(message)
    assert parsed['eventType'] == 'ERROR'
    assert parsed['errorMessage'] == 'Test error'


def test_build_error_subject_line():
    """Test building error notification subject lines."""
    subject = build_error_subject_line(ErrorCategory.PARSING, ErrorSeverity.MEDIUM)
    assert '[Identity Center]' in subject
    assert 'MEDIUM' in subject
    assert 'PARSING' in subject
    
    subject = build_error_subject_line(ErrorCategory.PERMANENT, ErrorSeverity.HIGH)
    assert 'HIGH' in subject
    assert 'PERMANENT' in subject


def test_handle_malformed_event_with_minimal_data():
    """Test handling malformed event with minimal data."""
    event = {'id': 'test-123'}
    exception = EventParsingError("Missing detail field")
    
    result = handle_malformed_event(event, exception)
    
    assert result['shouldNotify'] is True
    assert result['shouldRemediate'] is False
    assert result['error']['context']['eventId'] == 'test-123'


def test_handle_malformed_event_with_partial_data():
    """Test handling malformed event with partial data."""
    event = {
        'id': 'test-123',
        'account': '123456789012',
        'source': 'aws.sso',
        'time': '2025-12-16T10:00:00Z',
        'detail': {
            'eventName': 'CreateApplicationAssignment'
        }
    }
    exception = EventParsingError("Missing requestParameters")
    
    result = handle_malformed_event(event, exception)
    
    assert result['shouldNotify'] is True
    assert result['shouldRemediate'] is False
    assert result['error']['context']['accountId'] == '123456789012'
    assert result['error']['context']['eventName'] == 'CreateApplicationAssignment'


# Strategies for generating various exception types
@st.composite
def random_exception(draw):
    """Generate random exceptions of various types."""
    exception_type = draw(st.sampled_from([
        RuntimeError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        IndexError,
        ZeroDivisionError
    ]))
    
    message = draw(st.text(min_size=1, max_size=100))
    return exception_type(message)


@st.composite
def random_event_data(draw):
    """Generate random event data for context."""
    event = {}
    
    if draw(st.booleans()):
        event['id'] = draw(st.uuids().map(str))
    
    if draw(st.booleans()):
        event['source'] = draw(st.text(min_size=1, max_size=50))
    
    if draw(st.booleans()):
        event['account'] = draw(st.text(
            alphabet=st.characters(whitelist_categories=('Nd',)),
            min_size=12,
            max_size=12
        ))
    
    return event


@st.composite
def random_parsed_data(draw):
    """Generate random parsed data for context."""
    parsed = {}
    
    if draw(st.booleans()):
        parsed['application_arn'] = draw(st.text(min_size=10, max_size=100))
    
    if draw(st.booleans()):
        parsed['principal_id'] = draw(st.uuids().map(str))
    
    if draw(st.booleans()):
        parsed['account_id'] = draw(st.text(
            alphabet=st.characters(whitelist_categories=('Nd',)),
            min_size=12,
            max_size=12
        ))
    
    return parsed


# **Feature: identity-center-app-monitor, Property 13: Global exception handling**
# **Validates: Requirements 9.5**
@given(
    exception=random_exception(),
    event=random_event_data(),
    parsed_data=random_parsed_data()
)
def test_property_global_exception_handling(exception, event, parsed_data):
    """
    Property 13: Global exception handling
    
    For any unexpected exception during processing, the system should catch
    the exception, log it with full context, send an error notification,
    and complete without crashing.
    
    Validates: Requirements 9.5
    """
    # Handle the global exception
    result = handle_global_exception(
        exception=exception,
        event=event if event else None,
        parsed_data=parsed_data if parsed_data else None
    )
    
    # Verify the result structure
    assert 'error' in result
    assert 'shouldNotify' in result
    assert 'shouldRemediate' in result
    
    # Verify notification should be sent
    assert result['shouldNotify'] is True
    
    # Verify remediation should NOT be attempted
    assert result['shouldRemediate'] is False
    
    # Verify error notification contains required fields
    error = result['error']
    assert 'timestamp' in error
    assert 'eventType' in error
    assert error['eventType'] == 'ERROR'
    assert 'severity' in error
    assert 'errorCategory' in error
    assert 'errorMessage' in error
    assert 'errorType' in error
    # The stack trace must NOT reach the notification: this payload is published
    # to SNS, and a traceback carries whatever the exception message interpolated,
    # which in this codebase is routinely a principal ID. It is logged to
    # CloudWatch instead, where IAM controls who can read it.
    assert 'stackTrace' not in error
    assert 'context' in error
    
    # Verify error message contains the exception message
    assert str(exception) in error['errorMessage'] or error['errorMessage'] != ''
    
    # Verify error type is captured
    assert error['errorType'] == type(exception).__name__
    
    # Verify context is populated from available data
    context = error['context']
    if event and 'id' in event:
        assert context['eventId'] == event['id']
    
    # Account ID: parsed_data takes precedence over event
    if parsed_data and 'account_id' in parsed_data:
        assert context['accountId'] == parsed_data['account_id']
    elif event and 'account' in event:
        assert context['accountId'] == event['account']
    
    if parsed_data and 'application_arn' in parsed_data:
        assert context['applicationArn'] == parsed_data['application_arn']
    if parsed_data and 'principal_id' in parsed_data:
        # Held as a digest, never raw. Stated as a property over every principal
        # hypothesis generates rather than one example: the notification goes to
        # SNS, so "no raw principal ID reaches the payload" has to hold for all
        # inputs, not just the one a unit test happened to pick.
        assert context['principalDigest'] == principal_digest(parsed_data['principal_id'])
        assert 'principalId' not in context
        assert parsed_data['principal_id'] not in json.dumps(result)


# Unit tests for error scenarios


def test_service_unavailable_error_handling():
    """
    Test service unavailable error handling.
    
    Service unavailable errors should be categorized as TRANSIENT
    and have MEDIUM severity.
    """
    # Create a service unavailable error
    error_response = {
        'Error': {
            'Code': 'ServiceUnavailableException',
            'Message': 'Service is temporarily unavailable'
        }
    }
    exception = ClientError(error_response, 'DescribeApplication')
    
    # Categorize the error
    category = categorize_error(exception)
    assert category == ErrorCategory.TRANSIENT
    
    # Check severity
    severity = determine_severity(category)
    assert severity == ErrorSeverity.MEDIUM
    
    # Build error notification
    notification = build_error_notification(exception)
    
    assert notification['errorCategory'] == ErrorCategory.TRANSIENT.value
    assert notification['severity'] == ErrorSeverity.MEDIUM.value
    assert 'Service is temporarily unavailable' in notification['errorMessage']


def test_parsing_error_handling():
    """
    Test parsing error handling.
    
    Parsing errors should be categorized as PARSING and have MEDIUM severity.
    """
    # Create a parsing error
    exception = EventParsingError("Missing ApplicationArn field")
    
    # Categorize the error
    category = categorize_error(exception)
    assert category == ErrorCategory.PARSING
    
    # Check severity
    severity = determine_severity(category)
    assert severity == ErrorSeverity.MEDIUM
    
    # Build error notification
    notification = build_error_notification(exception)
    
    assert notification['errorCategory'] == ErrorCategory.PARSING.value
    assert notification['severity'] == ErrorSeverity.MEDIUM.value
    assert 'Missing ApplicationArn field' in notification['errorMessage']


def test_unexpected_exception_handling():
    """
    Test unexpected exception handling.
    
    Unexpected exceptions should be categorized as UNEXPECTED and have HIGH severity.
    """
    # Create an unexpected exception
    exception = RuntimeError("Unexpected error occurred")
    
    # Categorize the error
    category = categorize_error(exception)
    assert category == ErrorCategory.UNEXPECTED
    
    # Check severity
    severity = determine_severity(category)
    assert severity == ErrorSeverity.HIGH
    
    # Build error notification
    notification = build_error_notification(exception)
    
    assert notification['errorCategory'] == ErrorCategory.UNEXPECTED.value
    assert notification['severity'] == ErrorSeverity.HIGH.value
    assert 'Unexpected error occurred' in notification['errorMessage']


def test_handle_global_exception_with_full_context():
    """
    Test global exception handler with full context information.
    """
    exception = ValueError("Invalid value")
    event = {
        'id': 'event-123',
        'source': 'aws.sso',
        'account': '123456789012'
    }
    parsed_data = {
        'application_arn': 'arn:aws:sso:::application/test',
        'principal_id': 'principal-456',
        'account_id': '123456789012'
    }
    
    result = handle_global_exception(exception, event, parsed_data)
    
    # Verify result structure
    assert result['shouldNotify'] is True
    assert result['shouldRemediate'] is False
    
    # Verify context is populated
    context = result['error']['context']
    assert context['eventId'] == 'event-123'
    assert context['eventSource'] == 'aws.sso'
    assert context['accountId'] == '123456789012'
    assert context['applicationArn'] == 'arn:aws:sso:::application/test'
    # A digest, not the raw principal ID: this context is embedded in the SNS
    # notification, so it reaches every subscriber. Assert both halves -- that the
    # digest is present and stable, and that the raw identifier is absent -- because
    # asserting only the digest would still pass if the raw value were added back
    # alongside it.
    assert 'principalId' not in context
    assert context['principalDigest'] == principal_digest('principal-456')
    assert 'principal-456' not in json.dumps(result)


def test_handle_global_exception_with_no_context():
    """
    Test global exception handler with no context information.
    """
    exception = TypeError("Type error")
    
    result = handle_global_exception(exception, None, None)
    
    # Verify result structure
    assert result['shouldNotify'] is True
    assert result['shouldRemediate'] is False
    
    # Verify error notification is created
    assert 'error' in result
    assert result['error']['errorMessage'] == 'Type error'


def test_handle_malformed_event_extracts_available_context():
    """
    Test that handle_malformed_event extracts whatever context is available.
    """
    event = {
        'id': 'event-789',
        'source': 'aws.sso',
        'account': '987654321098',
        'time': '2025-12-16T12:00:00Z',
        'detail': {
            'eventName': 'CreateApplicationAssignment',
            'eventSource': 'sso.amazonaws.com'
        }
    }
    exception = EventParsingError("Missing requestParameters.ApplicationArn")
    
    result = handle_malformed_event(event, exception)
    
    # Verify context extraction
    context = result['error']['context']
    assert context['eventId'] == 'event-789'
    assert context['accountId'] == '987654321098'
    assert context['eventName'] == 'CreateApplicationAssignment'


def test_categorize_key_error_as_parsing():
    """Test that KeyError is categorized as PARSING."""
    exception = KeyError('missing_key')
    category = categorize_error(exception)
    assert category == ErrorCategory.PARSING


def test_categorize_value_error_as_parsing():
    """Test that ValueError is categorized as PARSING."""
    exception = ValueError('invalid value')
    category = categorize_error(exception)
    assert category == ErrorCategory.PARSING


def test_categorize_json_decode_error_as_parsing():
    """Test that JSONDecodeError is categorized as PARSING."""
    exception = json.JSONDecodeError('invalid json', '{"bad"}', 0)
    category = categorize_error(exception)
    assert category == ErrorCategory.PARSING
