"""
Event parsing module for Identity Center application assignment events.

This module extracts relevant information from CloudTrail events delivered via EventBridge.
"""

from typing import Dict, Any, Optional


class EventParsingError(Exception):
    """Raised when event parsing fails due to missing or invalid fields."""
    pass


def extract_application_arn(event: Dict[str, Any]) -> str:
    """
    Extract the application ARN from a CloudTrail event.
    
    Args:
        event: EventBridge event containing CloudTrail details
        
    Returns:
        Application ARN string
        
    Raises:
        EventParsingError: If application ARN cannot be extracted
    """
    try:
        request_params = event['detail']['requestParameters']
        # Try both capitalization variants (CloudTrail uses lowercase)
        return request_params.get('applicationArn') or request_params['ApplicationArn']
    except KeyError as e:
        raise EventParsingError(
            f"Failed to extract application ARN from event: missing field {e}"
        )


def extract_principal_info(event: Dict[str, Any]) -> tuple[str, str]:
    """
    Extract principal ID and type from a CloudTrail event.
    
    Args:
        event: EventBridge event containing CloudTrail details
        
    Returns:
        Tuple of (principal_id, principal_type)
        
    Raises:
        EventParsingError: If principal information cannot be extracted
    """
    try:
        request_params = event['detail']['requestParameters']
        # Try both capitalization variants (CloudTrail uses lowercase)
        principal_id = request_params.get('principalId') or request_params['PrincipalId']
        principal_type = request_params.get('principalType') or request_params['PrincipalType']
        return principal_id, principal_type
    except KeyError as e:
        raise EventParsingError(
            f"Failed to extract principal information from event: missing field {e}"
        )


def extract_account_id(event: Dict[str, Any]) -> str:
    """
    Extract the AWS account ID from a CloudTrail event.
    
    Args:
        event: EventBridge event containing CloudTrail details
        
    Returns:
        AWS account ID string
        
    Raises:
        EventParsingError: If account ID cannot be extracted
    """
    try:
        return event['account']
    except KeyError as e:
        raise EventParsingError(
            f"Failed to extract account ID from event: missing field {e}"
        )


def extract_instance_arn(event: Dict[str, Any]) -> str:
    """Extract Identity Center instance ARN from CloudTrail event."""
    try:
        request_params = event['detail']['requestParameters']
        instance_id = request_params.get('instanceId', '')
        if instance_id:
            return f"arn:aws:sso:::instance/{instance_id}"
        
        # Try from application ARN
        app_arn = request_params.get('applicationArn') or request_params.get('ApplicationArn', '')
        if app_arn and '/' in app_arn:
            return f"arn:aws:sso:::instance/{app_arn.split('/')[1]}"
        return ''
    except (KeyError, IndexError):
        return ''


def extract_directory_id(event: Dict[str, Any]) -> str:
    """Extract directory ID (Identity Store ID) from CloudTrail event."""
    try:
        return event['detail']['requestParameters'].get('directoryId', '')
    except KeyError:
        return ''


def extract_user_identity(event: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract IAM principal information from CloudTrail event.
    
    Args:
        event: EventBridge event containing CloudTrail details
        
    Returns:
        Dictionary with user identity information:
        - type: Identity type (e.g., AssumedRole, IAMUser, Root)
        - arn: Principal ARN
        - principalId: Principal ID
        - accountId: Account ID
    """
    try:
        user_identity = event['detail']['userIdentity']
        return {
            'type': user_identity.get('type', 'Unknown'),
            'arn': user_identity.get('arn', 'Unknown'),
            'principalId': user_identity.get('principalId', 'Unknown'),
            'accountId': user_identity.get('accountId', 'Unknown')
        }
    except (KeyError, TypeError):
        return {
            'type': 'Unknown',
            'arn': 'Unknown',
            'principalId': 'Unknown',
            'accountId': 'Unknown'
        }


def parse_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse a CloudTrail event and extract all relevant information.
    
    Args:
        event: EventBridge event containing CloudTrail details
        
    Returns:
        Dictionary containing parsed event data:
        - application_arn: Application ARN (or empty for profile events)
        - principal_id: Principal (user/group) ID (or accessorId for profile events)
        - principal_type: Type of principal (USER or GROUP, or accessorType for profile events)
        - account_id: AWS account ID
        - event_time: Event timestamp
        - event_name: CloudTrail event name
        - directory_id: Identity Store ID (for name resolution)
        - instance_arn: Identity Center instance ARN (for profile events)
        
    Raises:
        EventParsingError: If required fields cannot be extracted
    """
    try:
        account_id = extract_account_id(event)
        event_time = event.get('time', '')
        event_name = event.get('detail', {}).get('eventName', '')
        directory_id = extract_directory_id(event)
        instance_arn = extract_instance_arn(event)
        user_identity = extract_user_identity(event)
        
        # Profile events have different structure
        profile_events = ['CreateProfile', 'AssociateProfile', 'UpdateProfile',
                         'DisassociateProfile', 'DeleteProfile']

        # PutApplicationAssignmentConfiguration carries no principal at all --
        # its payload is {applicationArn, assignmentRequired}. Calling
        # extract_principal_info on it would raise EventParsingError, so it is
        # parsed on its own path. Key casing verified against a real CloudTrail
        # event: both keys are emitted lowerCamelCase, unlike the PascalCase API
        # parameter names.
        if event_name == 'PutApplicationAssignmentConfiguration':
            request_params = event.get('detail', {}).get('requestParameters', {})
            assignment_required = request_params.get('assignmentRequired')

            return {
                'application_arn': extract_application_arn(event),
                'principal_id': '',
                'principal_type': '',
                'account_id': account_id,
                'event_time': event_time,
                'event_name': event_name,
                'assignment_required': assignment_required,
                'directory_id': directory_id,
                'instance_arn': instance_arn,
                'user_identity': user_identity
            }

        if event_name in profile_events:
            # Profile events use different field names
            request_params = event.get('detail', {}).get('requestParameters', {})
            
            return {
                'application_arn': '',  # Profile events don't have application ARN
                'principal_id': request_params.get('accessorId', ''),
                'principal_type': request_params.get('accessorType', ''),
                'account_id': account_id,
                'event_time': event_time,
                'event_name': event_name,
                'profile_id': request_params.get('profileId', ''),
                'instance_id': request_params.get('instanceId', ''),
                'directory_id': directory_id or request_params.get('directoryId', ''),
                'instance_arn': instance_arn,
                'user_identity': user_identity
            }
        else:
            # Application assignment events
            application_arn = extract_application_arn(event)
            principal_id, principal_type = extract_principal_info(event)
            
            return {
                'application_arn': application_arn,
                'principal_id': principal_id,
                'principal_type': principal_type,
                'account_id': account_id,
                'event_time': event_time,
                'event_name': event_name,
                'directory_id': directory_id,
                'instance_arn': instance_arn,
                'user_identity': user_identity
            }
    except EventParsingError:
        # Re-raise parsing errors as-is
        raise
    except Exception as e:
        # Wrap unexpected errors
        raise EventParsingError(f"Unexpected error parsing event: {e}")
