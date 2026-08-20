# Assignment Discovery Lambda Function
# Discovers user and group assignments for IAM Identity Center applications
#
# PERSONAL DATA: this is the collection point. It resolves principal IDs against
# the Identity Store and persists principal_name, principal_display_name and
# principal_email to DynamoDB, so the rows written here name individuals and the
# applications they can reach. Everything downstream -- the CSV exports, the SNS
# notifications, the change log -- inherits that from this module.
#
# Under the AWS shared responsibility model the deploying account owns lawful
# basis, retention, data residency, access control, and erasure for it, which may
# engage the GDPR, UK GDPR, or CCPA/CPRA depending on the directory population.
# Log statements here redact principal identifiers through
# shared.utils.redact_principal; keep new ones consistent. See "Data protection
# and your compliance obligations" in the repository README.

import json
import boto3
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from shared.utils import setup_logging, handle_api_error, handle_access_denied_exception, get_aws_client, safe_api_call, redact_principal, redact_assignment_id
from shared.models import Assignment, DiscoveryResult, ValidationError, PrincipalType
from shared.tracing import (
    init_xray_tracing, trace_lambda_handler, trace_discovery_operation,
    trace_aws_api_call, add_discovery_metrics, trace_performance_bottleneck
)
try:
    from .edge_cases import handle_missing_principal, get_permission_set_details_with_fallback, validate_assignment_consistency
    from .matching import evaluate_group_application_match
except ImportError:
    from edge_cases import handle_missing_principal, get_permission_set_details_with_fallback, validate_assignment_consistency
    from matching import evaluate_group_application_match

# Initialize X-Ray tracing
init_xray_tracing("assignment-discovery")

logger = setup_logging(__name__)

# In-memory cache for application names during Lambda execution
_application_name_cache: Dict[str, str] = {}

@trace_lambda_handler
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for assignment discovery within IAM Identity Center applications
    
    Expected event format:
    {
        "application_arn": "arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
        "instance_arn": "arn:aws:sso:::instance/ssoins-1234567890abcdef",
        "account_id": "123456789012",
        "region": "us-east-1",
        "role_arn": "arn:aws:iam::123456789012:role/CrossAccountRole" (optional)
    }
    """
    logger.info("Starting assignment discovery")
    
    try:
        # Extract required parameters from event
        application_arn = event.get('application_arn')
        instance_arn = event.get('instance_arn')
        account_id = event.get('account_id')
        region = event.get('region')
        
        # Extract role_arn from discovery_metadata if present
        discovery_metadata = event.get('discovery_metadata', {})
        role_arn = event.get('role_arn') or discovery_metadata.get('role_arn')
        
        if not application_arn:
            raise ValueError("application_arn is required")
        if not instance_arn:
            raise ValueError("instance_arn is required")
        if not account_id:
            raise ValueError("account_id is required")
        if not region:
            raise ValueError("region is required")
        
        logger.info(f"Discovering assignments for application: {application_arn}")
        if role_arn:
            logger.info(f"Using cross-account role: {role_arn}")
        
        # Discover assignments
        discovery_result = discover_assignments(application_arn, instance_arn, account_id, region, role_arn)
        
        # Persist assignments to DynamoDB with change detection
        if discovery_result.data:
            table_name = os.environ.get('ASSIGNMENTS_TABLE')
            if table_name:
                try:
                    from .persistence import persist_assignments_with_change_detection
                except ImportError:
                    from persistence import persist_assignments_with_change_detection
                persistence_result = persist_assignments_with_change_detection(discovery_result.data, table_name)
                if not persistence_result.success:
                    discovery_result.errors.extend(persistence_result.errors)
                    discovery_result.success = False
            else:
                error_msg = "ASSIGNMENTS_TABLE environment variable not set"
                logger.error(error_msg)
                discovery_result.add_error(error_msg)
        
        logger.info(f"Assignment discovery completed. Found {len(discovery_result.data)} assignments")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': discovery_result.success,
                'message': discovery_result.message,
                'assignments': [assignment.to_dict() for assignment in discovery_result.data],
                'errors': discovery_result.errors,
                'count': len(discovery_result.data)
            })
        }
    
    except boto3.exceptions.Boto3Error as e:
        # Handle AWS SDK errors including AccessDeniedException
        if hasattr(e, 'response') and e.response.get('Error', {}).get('Code') == 'AccessDeniedException':
            return handle_access_denied_exception(e, context, application_arn or instance_arn)
        logger.error(f"Assignment discovery failed: {str(e)}")
        return handle_api_error(e)
        
    except Exception as e:
        logger.error(f"Assignment discovery failed: {str(e)}")
        return handle_api_error(e)

def discover_assignments(
    application_arn: str,
    instance_arn: str, 
    account_id: str, 
    region: str, 
    role_arn: Optional[str] = None
) -> DiscoveryResult:
    """
    Discover user and group assignments for an IAM Identity Center application
    
    Args:
        application_arn: Application ARN
        instance_arn: IAM Identity Center instance ARN
        account_id: AWS account ID
        region: AWS region
        role_arn: Optional cross-account role ARN
    
    Returns:
        DiscoveryResult containing discovered assignments
    """
    result = DiscoveryResult()
    
    try:
        # Create SSO Admin and Identity Store clients
        sso_client = get_aws_client('sso-admin', region, role_arn)
        
        # Extract identity store ID from instance ARN
        identity_store_id = extract_identity_store_id(sso_client, instance_arn)
        if not identity_store_id:
            error_msg = f"Could not determine identity store ID for instance: {instance_arn}"
            logger.error(error_msg)
            result.add_error(error_msg)
            return result
        
        identity_store_client = get_aws_client('identitystore', region, role_arn)
        
        logger.info(f"Listing assignments for application: {application_arn}")
        
        # List application assignments
        success, assignments_data, error = safe_api_call(
            lambda: list_application_assignments(sso_client, application_arn),
            f"Failed to list assignments for application {application_arn}"
        )
        
        if not success:
            # Check if this is an AccessDeniedException
            if 'AccessDeniedException' in error or 'is not authorized to perform' in error:
                logger.error("=" * 80)
                logger.error("ACCESS DENIED: sso:ListApplicationAssignments")
                logger.error("=" * 80)
                logger.error(f"Lambda Function: assignment-discovery")
                logger.error(f"Missing Permission: sso:ListApplicationAssignments")
                logger.error(f"Resource ARN: {application_arn}")
                logger.error(f"Error: {error}")
                logger.error("=" * 80)
            result.add_error(error)
            return result
        
        logger.info(f"Found {len(assignments_data)} assignments")
        
        # Process each assignment
        for assignment_data in assignments_data:
            try:
                assignment = process_assignment(
                    assignment_data, 
                    application_arn, 
                    instance_arn, 
                    account_id, 
                    identity_store_id,
                    sso_client, 
                    identity_store_client
                )
                
                if assignment:
                    result.add_data(assignment)
                    logger.debug(f"Successfully processed assignment: {redact_assignment_id(assignment.assignment_id)}")
                    
            except Exception as e:
                # Redacted here, at the point the string is built, not at the point
                # it is logged. This message has two consumers -- logger.warning
                # below and result.add_error, which carries it into the discovery
                # result and from there into the run's error report -- so redacting
                # only at the log call would still publish the raw ID through the
                # other one.
                error_msg = (
                    f"Error processing assignment "
                    f"{redact_principal(assignment_data.get('PrincipalId', 'unknown'))}: {str(e)}"
                )
                logger.warning(error_msg)
                result.add_error(error_msg)
                continue
        
        # Validate assignment consistency and log warnings
        validation_result = validate_assignment_consistency(result.data, application_arn)
        for warning in validation_result.get('warnings', []):
            logger.warning(f"Assignment validation warning: {warning}")
            result.add_error(f"Validation warning: {warning}")
        
        result.message = f"Successfully discovered {len(result.data)} assignments"
        logger.info(result.message)
        
    except Exception as e:
        error_msg = f"Failed to discover assignments: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result

def extract_identity_store_id(sso_client: boto3.client, instance_arn: str) -> Optional[str]:
    """
    Extract identity store ID from instance ARN by describing the instance
    
    Args:
        sso_client: SSO Admin client
        instance_arn: Instance ARN
    
    Returns:
        Identity store ID or None if not found
    """
    try:
        success, instance_data, error = safe_api_call(
            lambda: sso_client.describe_instance(InstanceArn=instance_arn),
            f"Failed to describe instance {instance_arn}",
            continue_on_error=True
        )
        
        if success:
            return instance_data.get('IdentityStoreId')
        else:
            # Check if this is an AccessDeniedException
            if 'AccessDeniedException' in error or 'is not authorized to perform' in error:
                logger.error("=" * 80)
                logger.error("ACCESS DENIED: sso:DescribeInstance")
                logger.error("=" * 80)
                logger.error(f"Lambda Function: assignment-discovery")
                logger.error(f"Missing Permission: sso:DescribeInstance")
                logger.error(f"Resource ARN: {instance_arn}")
                logger.error(f"Error: {error}")
                logger.error("=" * 80)
            logger.warning(f"Could not get identity store ID: {error}")
            return None
            
    except Exception as e:
        logger.warning(f"Error extracting identity store ID: {str(e)}")
        return None

def list_application_assignments(sso_client: boto3.client, application_arn: str) -> List[Dict[str, Any]]:
    """
    List all assignments for an application with pagination
    
    Args:
        sso_client: SSO Admin client
        application_arn: Application ARN
    
    Returns:
        List of assignment data dictionaries
    """
    assignments = []
    next_token = None
    
    while True:
        try:
            params = {
                'ApplicationArn': application_arn,
                'MaxResults': 100
            }
            
            if next_token:
                params['NextToken'] = next_token
            
            response = sso_client.list_application_assignments(**params)
            
            assignments.extend(response.get('ApplicationAssignments', []))
            
            next_token = response.get('NextToken')
            if not next_token:
                break
                
        except Exception as e:
            logger.error(f"Error listing application assignments: {str(e)}")
            raise
    
    return assignments

class PrincipalLookupFailed(Exception):
    # The message must carry a redacted principal, never a raw one.
    #
    # An exception message is not a private channel: it is logged by the handler
    # below, and str(exception) is what error reporting puts in its notification
    # payload. Every raise site here sits directly under a logger call that already
    # redacts the same value, so interpolating the raw ID one line later undid the
    # redaction and put the identifier back in CloudWatch.
    """
    Raised when a principal lookup could not be completed.

    Distinct from "the principal does not exist". A resolver returning None means
    the Identity Store confirmed the principal is gone, which legitimately marks
    the assignment as a deleted principal. Any OTHER failure -- AccessDenied from
    a cross-account role missing identitystore:DescribeGroup, throttling, expired
    credentials -- means we simply do not know. Collapsing the two would report
    every assignment in an instance as "[DELETED GROUP]" purely because one
    permission was missing, which reads as mass access revocation in the report.
    """


def process_assignment(
    assignment_data: Dict[str, Any],
    application_arn: str,
    instance_arn: str,
    account_id: str,
    identity_store_id: str,
    sso_client: boto3.client,
    identity_store_client: boto3.client
) -> Optional[Assignment]:
    """
    Process a single assignment and retrieve principal details
    
    Args:
        assignment_data: Assignment data from AWS API
        application_arn: Application ARN
        instance_arn: Instance ARN
        account_id: Account ID
        identity_store_id: Identity Store ID
        sso_client: SSO Admin client
        identity_store_client: Identity Store client
    
    Returns:
        Assignment object or None if processing failed
    """
    try:
        principal_id = assignment_data.get('PrincipalId')
        principal_type = assignment_data.get('PrincipalType')
        
        if not principal_id or not principal_type:
            logger.warning("Assignment missing principal ID or type")
            return None
        
        logger.debug("Processing %s assignment: %s", principal_type, redact_principal(principal_id))
        
        # Get principal details based on type
        if principal_type == PrincipalType.USER.value:
            principal_details = get_user_details(identity_store_client, identity_store_id, principal_id)
        elif principal_type == PrincipalType.GROUP.value:
            principal_details = get_group_details(identity_store_client, identity_store_id, principal_id)
        else:
            logger.warning(f"Unknown principal type: {principal_type}")
            return None
        
        # Handle case where principal no longer exists in Identity Provider.
        # A None here means the Identity Store confirmed absence. A lookup that
        # could not complete raises PrincipalLookupFailed and is handled by the
        # caller, so a missing permission is never reported as a deletion.
        if not principal_details:
            return handle_missing_principal(
                assignment_data, application_arn, instance_arn, account_id, principal_type, principal_id
            )
        
        # Extract principal information
        principal_name = principal_details.get('principal_name')
        principal_display_name = principal_details.get('principal_display_name')
        principal_email = principal_details.get('principal_email')
        
        # Get permission set details with fallback handling
        permission_set_arn = assignment_data.get('PermissionSetArn')
        permission_set_details = get_permission_set_details_with_fallback(
            sso_client, instance_arn, permission_set_arn
        )
        permission_set_name = permission_set_details['permission_set_name']
        
        # Create assignment ID
        assignment_id = Assignment.create_assignment_id(application_arn, principal_id)
        
        # Retrieve application name for matching logic
        application_name = get_application_name(application_arn, instance_arn)
        
        # Evaluate group-application matching
        matching_result = evaluate_group_application_match(
            principal_type=principal_type,
            principal_name=principal_name,
            application_name=application_name,
            group_name_regex=os.environ.get('GROUP_NAME_REGEX') or None
        )
        
        # Prepare matched field with matching result
        matched = None
        if matching_result:  # Only add matched if matching was performed (not empty string for USER)
            matched = matching_result
        
        # Create Assignment object
        assignment = Assignment(
            assignment_id=assignment_id,
            application_arn=application_arn,
            principal_id=principal_id,
            principal_type=principal_type,
            principal_name=principal_name,
            principal_display_name=principal_display_name,
            principal_email=principal_email,
            permission_set_arn=permission_set_arn,
            permission_set_name=permission_set_name,
            account_id=account_id,
            instance_arn=instance_arn,
            assignment_status='ACTIVE',  # Default to active for discovered assignments
            matched=matched
        )
        
        return assignment

    except PrincipalLookupFailed as e:
        # Re-raised so the caller records a real error instead of the assignment
        # silently vanishing from a report that still claims success.
        logger.error(f"Assignment skipped -- principal lookup incomplete: {e}")
        raise
    except Exception as e:
        logger.error(f"Error processing assignment: {str(e)}")
        return None

def get_user_details(identity_store_client: boto3.client, identity_store_id: str, user_id: str) -> Optional[Dict[str, str]]:
    """
    Retrieve user details from Identity Store using identitystore:DescribeUser
    
    Args:
        identity_store_client: Identity Store client
        identity_store_id: Identity Store ID
        user_id: User ID
    
    Returns:
        Dictionary with user details (name, display_name, email) or None if not found
    """
    try:
        success, user_data, error = safe_api_call(
            lambda: identity_store_client.describe_user(
                IdentityStoreId=identity_store_id,
                UserId=user_id
            ),
            f"Failed to describe user {user_id}",
            continue_on_error=True
        )
        
        if success:
            # Extract user details
            user_name = user_data.get('UserName')
            display_name = user_data.get('DisplayName')
            
            # Check for email in emails array
            emails = user_data.get('Emails', [])
            primary_email = None
            for email in emails:
                if email.get('Primary', False):
                    primary_email = email.get('Value')
                    break
            
            # If no primary email, get first email
            if not primary_email and emails:
                primary_email = emails[0].get('Value')
            
            # Determine the best principal name
            principal_name = primary_email or display_name or user_name or user_id
            
            return {
                'principal_name': principal_name,
                'principal_display_name': display_name or '',
                'principal_email': primary_email or ''
            }
        else:
            # Only a confirmed absence means the user was deleted.
            if error and 'ResourceNotFound' in str(error):
                logger.warning("User %s not found in Identity Store (deleted)", redact_principal(user_id))
                return None
            logger.error("User lookup failed for %s, cannot classify: %s", redact_principal(user_id), error)
            raise PrincipalLookupFailed(f"user {redact_principal(user_id)}: {error}")

    except PrincipalLookupFailed:
        raise
    except Exception as e:
        logger.error("User lookup failed for %s, cannot classify: %s", redact_principal(user_id), str(e))
        raise PrincipalLookupFailed(f"user {redact_principal(user_id)}: {e}")

def get_group_details(identity_store_client: boto3.client, identity_store_id: str, group_id: str) -> Optional[Dict[str, str]]:
    """
    Retrieve group details from Identity Store using identitystore:DescribeGroup
    
    Args:
        identity_store_client: Identity Store client
        identity_store_id: Identity Store ID
        group_id: Group ID
    
    Returns:
        Dictionary with group details (name, display_name) or None if not found
    """
    try:
        success, group_data, error = safe_api_call(
            lambda: identity_store_client.describe_group(
                IdentityStoreId=identity_store_id,
                GroupId=group_id
            ),
            f"Failed to describe group {group_id}",
            continue_on_error=True
        )
        
        if success:
            # Try to get the most descriptive name available
            display_name = group_data.get('DisplayName')
            group_name = group_data.get('GroupName')
            
            principal_name = display_name or group_name or group_id
            
            return {
                'principal_name': principal_name,
                'principal_display_name': display_name or '',
                'principal_email': ''  # Groups don't have emails
            }
        else:
            # Only a confirmed absence means the group was deleted.
            if error and 'ResourceNotFound' in str(error):
                logger.warning("Group %s not found in Identity Store (deleted)", redact_principal(group_id))
                return None
            logger.error("Group lookup failed for %s, cannot classify: %s", redact_principal(group_id), error)
            raise PrincipalLookupFailed(f"group {redact_principal(group_id)}: {error}")

    except PrincipalLookupFailed:
        raise
    except Exception as e:
        logger.error("Group lookup failed for %s, cannot classify: %s", redact_principal(group_id), str(e))
        raise PrincipalLookupFailed(f"group {redact_principal(group_id)}: {e}")

def persist_assignments_to_dynamodb(assignments: List[Assignment]) -> DiscoveryResult:
    """
    Persist discovered assignments to DynamoDB with validation and upsert logic
    
    Args:
        assignments: List of Assignment objects to persist
    
    Returns:
        DiscoveryResult indicating success/failure of persistence operations
    """
    result = DiscoveryResult()
    
    try:
        # Get DynamoDB table name from environment
        table_name = os.environ.get('ASSIGNMENTS_TABLE')
        if not table_name:
            error_msg = "ASSIGNMENTS_TABLE environment variable not set"
            logger.error(error_msg)
            result.add_error(error_msg)
            return result
        
        # Create DynamoDB client
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)
        
        logger.info(f"Persisting {len(assignments)} assignments to DynamoDB table: {table_name}")
        
        # Process assignments in batches for better performance
        batch_size = 25  # DynamoDB batch write limit
        for i in range(0, len(assignments), batch_size):
            batch = assignments[i:i + batch_size]
            batch_result = persist_assignment_batch(table, batch)
            
            if not batch_result.success:
                result.errors.extend(batch_result.errors)
                result.success = False
            else:
                result.data.extend(batch_result.data)
        
        if result.success:
            result.message = f"Successfully persisted {len(result.data)} assignments to DynamoDB"
            logger.info(result.message)
        else:
            result.message = f"Persistence completed with errors. {len(result.data)} successful, {len(result.errors)} errors"
            logger.warning(result.message)
        
    except Exception as e:
        error_msg = f"Failed to persist assignments to DynamoDB: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result

def persist_assignment_batch(table: boto3.resource, assignments: List[Assignment]) -> DiscoveryResult:
    """
    Persist a batch of assignments to DynamoDB
    
    Args:
        table: DynamoDB table resource
        assignments: List of Assignment objects to persist
    
    Returns:
        DiscoveryResult for the batch operation
    """
    result = DiscoveryResult()
    
    try:
        # Prepare batch write items
        with table.batch_writer() as batch:
            for assignment in assignments:
                try:
                    # Validate assignment before writing
                    assignment.validate()
                    
                    # Convert to DynamoDB item format
                    item = prepare_assignment_item(assignment)
                    
                    # Write to DynamoDB with upsert logic
                    batch.put_item(Item=item)
                    result.add_data(assignment)
                    
                    logger.debug(f"Queued assignment for batch write: {redact_assignment_id(assignment.assignment_id)}")
                    
                except ValidationError as e:
                    error_msg = f"Validation failed for assignment {redact_assignment_id(assignment.assignment_id)}: {str(e)}"
                    logger.warning(error_msg)
                    result.add_error(error_msg)
                    continue
                    
                except Exception as e:
                    error_msg = f"Error preparing assignment {redact_assignment_id(assignment.assignment_id)} for write: {str(e)}"
                    logger.warning(error_msg)
                    result.add_error(error_msg)
                    continue
        
        logger.info(f"Batch write completed for {len(result.data)} assignments")
        
    except Exception as e:
        error_msg = f"Batch write failed: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result

def prepare_assignment_item(assignment: Assignment) -> Dict[str, Any]:
    """
    Prepare assignment data for DynamoDB storage with proper formatting
    
    Args:
        assignment: Assignment object to prepare
    
    Returns:
        Dictionary formatted for DynamoDB storage
    """
    # Start with the assignment's dictionary representation
    item = assignment.to_dict()
    
    # Ensure required fields are present
    if not item.get('last_updated'):
        item['last_updated'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    # Add discovery metadata
    item['discovery_metadata'] = {
        'discovered_by': 'assignment-discovery-lambda',
        'discovery_timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'version': '1.0'
    }
    
    # Remove None values to save space (but keep empty strings for optional fields)
    # Keep metadata field even if it's an empty dict or has values
    item = {k: v for k, v in item.items() if v is not None and (v != '' or k == 'metadata')}
    
    return item

def get_application_name(application_arn: str, instance_arn: str) -> Optional[str]:
    """
    Retrieve application name from DynamoDB with in-memory caching.

    This function queries the Applications DynamoDB table to get the application
    name for a given application ARN. Results are cached in memory for the
    duration of the Lambda execution to minimize DynamoDB queries.

    Args:
        application_arn: Application ARN to look up
        instance_arn: Instance ARN (table sort key)

    Returns:
        Application name if found, None if not found or on error
    """
    global _application_name_cache
    
    # Import X-Ray utilities
    try:
        from aws_xray_sdk.core import xray_recorder
        from aws_xray_sdk.core.exceptions import SegmentNotFoundException
        xray_available = True
    except ImportError:
        xray_available = False
    
    # Create X-Ray subsegment for application name retrieval
    if xray_available:
        try:
            subsegment = xray_recorder.begin_subsegment('get_application_name')
        except (SegmentNotFoundException, AttributeError):
            subsegment = None
    else:
        subsegment = None
    
    try:
        # Check cache first
        if application_arn in _application_name_cache:
            logger.debug(f"Cache hit for application: {application_arn}")
            
            # Add cache hit annotation
            if subsegment:
                subsegment.put_annotation('cache_hit', True)
                subsegment.put_annotation('cache_miss', False)
            
            return _application_name_cache[application_arn]
        
        logger.debug(f"Cache miss for application: {application_arn}")
        
        # Add cache miss annotation
        if subsegment:
            subsegment.put_annotation('cache_hit', False)
            subsegment.put_annotation('cache_miss', True)
        
        # Get table name from environment
        table_name = os.environ.get('APPLICATIONS_TABLE')
        if not table_name:
            logger.error("APPLICATIONS_TABLE environment variable not set")
            if subsegment:
                subsegment.put_annotation('error', True)
                subsegment.put_metadata('error_details', {
                    'error_type': 'ConfigurationError',
                    'error_message': 'APPLICATIONS_TABLE environment variable not set'
                })
            return None
        
        # Query DynamoDB
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)
        
        # The applications table has a composite key (application_arn HASH,
        # instance_arn RANGE) — GetItem with only the hash key raises
        # ValidationException.
        response = table.get_item(
            Key={
                'application_arn': application_arn,
                'instance_arn': instance_arn
            }
        )
        
        # Extract application name
        item = response.get('Item')
        if item:
            name = item.get('name')
            if name:
                # Cache the result
                _application_name_cache[application_arn] = name
                logger.debug(f"Cached application name: {name} for ARN: {application_arn}")
                
                # Add success annotation
                if subsegment:
                    subsegment.put_annotation('application_found', True)
                    subsegment.put_metadata('application_details', {
                        'application_arn': application_arn,
                        'application_name': name
                    })
                
                return name
            else:
                logger.warning(f"Application found but 'name' field missing for ARN: {application_arn}")
                if subsegment:
                    subsegment.put_annotation('application_found', False)
                    subsegment.put_annotation('missing_name_field', True)
                return None
        else:
            logger.warning(f"Application not found in DynamoDB: {application_arn}")
            if subsegment:
                subsegment.put_annotation('application_found', False)
            return None
    
    except Exception as e:
        logger.error(f"Error retrieving application name for {application_arn}: {str(e)}")
        
        # Add error annotation
        if subsegment:
            subsegment.put_annotation('error', True)
            subsegment.put_metadata('error_details', {
                'error_type': type(e).__name__,
                'error_message': str(e)
            })
        
        return None
    
    finally:
        # End the subsegment
        if subsegment and xray_available:
            try:
                xray_recorder.end_subsegment()
            except Exception:
                pass