"""
Property-based tests for event parsing module.

Feature: identity-center-app-monitor
"""

import pytest
from hypothesis import given, strategies as st
from event_parser import (
    extract_application_arn,
    extract_principal_info,
    extract_account_id,
    parse_event,
    EventParsingError
)


# Strategies for generating valid event components
@st.composite
def valid_cloudtrail_event(draw):
    """Generate a valid CloudTrail event structure for Identity Center assignments."""
    application_arn = draw(st.text(
        alphabet=st.characters(min_codepoint=33, max_codepoint=126),
        min_size=20,
        max_size=200
    ).filter(lambda x: 'arn:aws:sso' in x or len(x) > 30))
    
    principal_id = draw(st.uuids().map(str))
    principal_type = draw(st.sampled_from(['USER', 'GROUP']))
    account_id = draw(st.text(
        alphabet=st.characters(whitelist_categories=('Nd',)),
        min_size=12,
        max_size=12
    ))
    event_time = draw(st.datetimes().map(lambda dt: dt.isoformat() + 'Z'))
    event_name = draw(st.sampled_from([
        'CreateApplicationAssignment',
        'DeleteApplicationAssignment'
    ]))
    
    return {
        'version': '0',
        'id': draw(st.uuids().map(str)),
        'detail-type': 'AWS API Call via CloudTrail',
        'source': 'aws.sso',
        'account': account_id,
        'time': event_time,
        'region': draw(st.sampled_from(['us-east-1', 'us-west-2', 'eu-west-1'])),
        'detail': {
            'eventVersion': '1.08',
            'eventID': draw(st.uuids().map(str)),
            'eventName': event_name,
            'eventTime': event_time,
            'eventSource': 'sso.amazonaws.com',
            'requestParameters': {
                'ApplicationArn': application_arn,
                'PrincipalId': principal_id,
                'PrincipalType': principal_type
            },
            'responseElements': {}
        }
    }


# **Feature: identity-center-app-monitor, Property 1: Event parsing completeness**
# **Validates: Requirements 2.1, 2.2**
@given(event=valid_cloudtrail_event())
def test_property_event_parsing_completeness(event):
    """
    Property 1: Event parsing completeness
    
    For any valid CloudTrail event for Identity Center application assignments,
    the system should successfully extract both the application ARN and principal ID
    (group ID) from the event payload.
    
    Validates: Requirements 2.1, 2.2
    """
    # Parse the event
    parsed = parse_event(event)
    
    # Verify all required fields are extracted
    assert 'application_arn' in parsed
    assert 'principal_id' in parsed
    assert 'principal_type' in parsed
    assert 'account_id' in parsed
    
    # Verify extracted values match the input
    assert parsed['application_arn'] == event['detail']['requestParameters']['ApplicationArn']
    assert parsed['principal_id'] == event['detail']['requestParameters']['PrincipalId']
    assert parsed['principal_type'] == event['detail']['requestParameters']['PrincipalType']
    assert parsed['account_id'] == event['account']


def test_extract_application_arn_missing_field():
    """Test that missing application ARN raises appropriate error."""
    event = {'detail': {'requestParameters': {}}}
    
    with pytest.raises(EventParsingError) as exc_info:
        extract_application_arn(event)
    
    assert 'ApplicationArn' in str(exc_info.value)


def test_extract_principal_info_missing_field():
    """Test that missing principal info raises appropriate error."""
    event = {'detail': {'requestParameters': {'PrincipalId': 'test-id'}}}
    
    with pytest.raises(EventParsingError) as exc_info:
        extract_principal_info(event)
    
    assert 'PrincipalType' in str(exc_info.value)


def test_extract_account_id_missing_field():
    """Test that missing account ID raises appropriate error."""
    event = {'detail': {}}
    
    with pytest.raises(EventParsingError) as exc_info:
        extract_account_id(event)
    
    assert 'account' in str(exc_info.value)


def test_parse_associate_profile_event():
    """Test parsing of AssociateProfile events."""
    event = {
        'version': '0',
        'id': 'test-id',
        'detail-type': 'AWS API Call via CloudTrail',
        'source': 'aws.sso',
        'account': '123456789012',
        'time': '2025-12-16T18:59:06Z',
        'region': 'us-east-1',
        'detail': {
            'eventName': 'AssociateProfile',
            'eventSource': 'sso.amazonaws.com',
            'requestParameters': {
                'accessorId': '11111111-1111-1111-1111-111111111111',
                'accessorType': 'GROUP',
                'directoryId': 'd-EXAMPLE123',
                'instanceId': 'ins-EXAMPLE123456789',
                'profileId': 'p-EXAMPLE123456789'
            }
        }
    }
    
    parsed = parse_event(event)
    
    # Verify profile event fields
    assert parsed['event_name'] == 'AssociateProfile'
    assert parsed['principal_id'] == '11111111-1111-1111-1111-111111111111'
    assert parsed['principal_type'] == 'GROUP'
    assert parsed['directory_id'] == 'd-EXAMPLE123'
    assert parsed['profile_id'] == 'p-EXAMPLE123456789'
    assert parsed['instance_id'] == 'ins-EXAMPLE123456789'
    assert parsed['application_arn'] == ''  # Profile events don't have application ARN


# **Feature: identity-center-app-monitor, Property 9: Account ID extraction**
# **Validates: Requirements 6.3**
@given(event=valid_cloudtrail_event())
def test_property_account_id_extraction(event):
    """
    Property 9: Account ID extraction
    
    For any CloudTrail event, the system should correctly extract and identify
    the AWS account ID from which the event originated.
    
    Validates: Requirements 6.3
    """
    # Extract account ID
    account_id = extract_account_id(event)
    
    # Verify it matches the account field in the event
    assert account_id == event['account']
    
    # Verify it's a valid format (12 digits)
    assert len(account_id) == 12
    assert account_id.isdigit()


def test_parse_assignment_configuration_event_without_principal():
    """
    PutApplicationAssignmentConfiguration parses despite having no principal.

    Its requestParameters are {applicationArn, assignmentRequired}. Routing it
    through extract_principal_info would raise EventParsingError, so it has a
    dedicated parse path.
    """
    event = {
        'version': '0',
        'id': 'test-id',
        'detail-type': 'AWS API Call via CloudTrail',
        'source': 'aws.sso',
        'account': '123456789012',
        'time': '2025-12-15T10:30:00Z',
        'region': 'us-east-1',
        'detail': {
            'eventName': 'PutApplicationAssignmentConfiguration',
            'eventSource': 'sso.amazonaws.com',
            'requestParameters': {
                'applicationArn': 'arn:aws:sso:::application/ins-123/app-456',
                'assignmentRequired': False
            }
        }
    }

    parsed = parse_event(event)

    assert parsed['event_name'] == 'PutApplicationAssignmentConfiguration'
    assert parsed['application_arn'] == 'arn:aws:sso:::application/ins-123/app-456'
    assert parsed['assignment_required'] is False
    assert parsed['principal_id'] == ''
    assert parsed['principal_type'] == ''
    assert parsed['account_id'] == '123456789012'
