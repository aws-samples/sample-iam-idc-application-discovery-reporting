# Assignment Discovery Lambda Function
# Discovers assignments (users and groups) for IAM Identity Center applications
#
# PERSONAL DATA: this function resolves principal IDs to UserName, DisplayName,
# and email address from the Identity Store and persists them to DynamoDB, so
# the tables it writes identify named individuals and the applications they can
# reach.
#
# Under the AWS shared responsibility model the deploying account owns lawful
# basis, retention, data residency, access control, and erasure for it. Log
# statements in this module redact principal identifiers through
# shared.utils.redact_principal for the same reason -- keep new ones consistent.
# See "Data protection and your compliance obligations" in the repository README.

import json
import boto3
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from shared.utils import setup_logging, handle_api_error, get_aws_client, paginate_api_call, safe_api_call, redact_principal
from shared.models import Assignment, DiscoveryResult, ValidationError
from shared.tracing import (
    init_xray_tracing, trace_lambda_handler, trace_discovery_operation,
    trace_aws_api_call, add_discovery_metrics, trace_performance_bottleneck
)

# Initialize X-Ray tracing
init_xray_tracing("assignment-discovery")

logger = setup_logging(__name__)

@trace_lambda_handler
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for discovering application assignments
    
    Expected event format:
    {
        "application_arn": "arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
        "instance_arn": "arn:aws:sso:::instance/ssoins-1234567890abcdef",
        "discovery_run_id": "assignment-discovery-12345" (optional)
    }
    """
    logger.info("Starting assignment discovery")
    
    try:
        # Extract required parameters from event
        application_arn = event.get('application_arn')
        instance_arn = event.get('instance_arn')
        discovery_run_id = event.get('discovery_run_id', f"assignment-discovery-{int(datetime.now(timezone.utc).timestamp())}")
        
        if not application_arn:
            raise ValueError("application_arn is required")
        if not instance_arn:
            raise ValueError("instance_arn is required")
        
        logger.info(f"Discovering assignments for application: {application_arn}")
        
        # Discover assignments
        discovery_result = discover_assignments_for_application(
            application_arn, 
            instance_arn, 
            discovery_run_id
        )
        
        logger.info(f"Assignment discovery completed. Found {len(discovery_result.data)} assignments")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'success': discovery_result.success,
                'message': discovery_result.message,
                'assignments': [assignment.to_dict() for assignment in discovery_result.data],
                'errors': discovery_result.errors,
                'count': len(discovery_result.data),
                'discovery_run_id': discovery_run_id
            })
        }
        
    except Exception as e:
        logger.error(f"Assignment discovery failed: {str(e)}")
        return handle_api_error(e)

@trace_discovery_operation("assignment_discovery", {"component": "assignment-discovery"})
@trace_performance_bottleneck("assignment_discovery", 30.0)
def discover_assignments_for_application(
    application_arn: str,
    instance_arn: str, 
    discovery_run_id: str
) -> DiscoveryResult:
    """
    Discover assignments for a specific application
    
    Args:
        application_arn: ARN of the application
        instance_arn: ARN of the SSO instance
        discovery_run_id: Unique identifier for this discovery run
    
    Returns:
        DiscoveryResult containing discovered assignments
    """
    result = DiscoveryResult()
    
    try:
        # Create SSO Admin client
        sso_client = get_aws_client('sso-admin')
        
        logger.info(f"Listing assignments for application: {application_arn}")
        
        # List application assignments
        def _list_assignments():
            return paginate_api_call(
                sso_client,
                'list_application_assignments',
                ApplicationArn=application_arn
            )
        
        success, assignments_data, error = safe_api_call(
            _list_assignments,
            f"Failed to list assignments for application {application_arn}",
            continue_on_error=True
        )
        
        if not success:
            result.add_error(error)
            return result
        
        logger.info(f"Found {len(assignments_data)} assignments")
        
        # Get identity store ID from instance
        identity_store_id = get_identity_store_id_from_instance(sso_client, instance_arn)
        if not identity_store_id:
            result.add_error(f"Could not get identity store ID for instance {instance_arn}")
            return result
        
        # Process each assignment and get principal details
        for assignment in assignments_data:
            try:
                principal_id = assignment.get('PrincipalId')
                principal_type = assignment.get('PrincipalType')
                
                if not principal_id or not principal_type:
                    logger.warning("Assignment missing principal information, skipping")
                    continue
                
                # Get principal details (user or group information)
                principal_details = get_principal_details(
                    identity_store_id, 
                    principal_id, 
                    principal_type
                )
                
                # Create assignment ID
                assignment_id = f"{application_arn.split('/')[-1]}#{principal_id}"
                
                # Create Assignment model object
                assignment_obj = Assignment(
                    assignment_id=assignment_id,
                    application_arn=application_arn,
                    principal_id=principal_id,
                    principal_type=principal_type,
                    principal_name=principal_details.get('name', 'Unknown'),
                    instance_arn=instance_arn,
                    assignment_status='ACTIVE',
                    last_updated=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                )
                
                result.add_data(assignment_obj)
                logger.debug("Added assignment: %s %s", principal_type,
                             redact_principal(principal_details.get('name', principal_id)))
                
            except Exception as e:
                logger.error(
                        "Error processing assignment for %s (principal %s): %s",
                        assignment.get("ApplicationArn", "unknown"),
                        redact_principal(assignment.get("PrincipalId")), str(e)
                    )
                result.add_error(f"Error processing assignment: {str(e)}")
                continue
        
        if result.data:
            result.message = f"Successfully discovered {len(result.data)} assignments"
        else:
            result.message = "No assignments found for this application"
        
        logger.info(f"Successfully processed {len(result.data)} assignments")
        
    except Exception as e:
        error_msg = f"Error discovering assignments for application {application_arn}: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result

def get_identity_store_id_from_instance(sso_client: boto3.client, instance_arn: str) -> Optional[str]:
    """
    Get the identity store ID for a given SSO instance
    
    Args:
        sso_client: SSO Admin client
        instance_arn: ARN of the SSO instance
    
    Returns:
        Identity store ID or None if not found
    """
    try:
        def _describe_instance():
            return sso_client.describe_instance(InstanceArn=instance_arn)
        
        success, result, error = safe_api_call(
            _describe_instance,
            f"Failed to describe instance {instance_arn}",
            continue_on_error=True
        )
        
        if success:
            return result.get('IdentityStoreId')
        else:
            logger.warning(f"Could not describe instance {instance_arn}: {error}")
            return None
            
    except Exception as e:
        logger.error(f"Error getting identity store ID for instance {instance_arn}: {str(e)}")
        return None

def get_principal_details(
    identity_store_id: str, 
    principal_id: str, 
    principal_type: str
) -> Dict[str, Any]:
    """
    Get details for a principal (user or group) from the identity store
    
    Args:
        identity_store_id: ID of the identity store
        principal_id: ID of the principal
        principal_type: Type of principal ('USER' or 'GROUP')
    
    Returns:
        Dictionary with principal details
    """
    details = {
        'name': 'Unknown',
        'display_name': None,
        'email': None
    }
    
    try:
        # Create identity store client
        identity_client = get_aws_client('identitystore')
        
        if principal_type == 'USER':
            def _describe_user():
                return identity_client.describe_user(
                    IdentityStoreId=identity_store_id,
                    UserId=principal_id
                )
            
            success, result, error = safe_api_call(
                _describe_user,
                f"Failed to describe user {principal_id}",
                continue_on_error=True
            )
            
            if success:
                user_data = result
                details['name'] = user_data.get('UserName', principal_id)
                details['display_name'] = user_data.get('DisplayName')
                
                # Get primary email
                emails = user_data.get('Emails', [])
                for email in emails:
                    if email.get('Primary', False):
                        details['email'] = email.get('Value')
                        break
                
                logger.debug("Retrieved user details: %s", redact_principal(details['name']))
            else:
                logger.warning("Could not describe user %s: %s", redact_principal(principal_id), error)
                details['name'] = f"User-{principal_id}"
        
        elif principal_type == 'GROUP':
            def _describe_group():
                return identity_client.describe_group(
                    IdentityStoreId=identity_store_id,
                    GroupId=principal_id
                )
            
            success, result, error = safe_api_call(
                _describe_group,
                f"Failed to describe group {principal_id}",
                continue_on_error=True
            )
            
            if success:
                group_data = result
                details['name'] = group_data.get('DisplayName', principal_id)
                details['display_name'] = group_data.get('DisplayName')
                
                logger.debug("Retrieved group details: %s", redact_principal(details['name']))
            else:
                logger.warning("Could not describe group %s: %s", redact_principal(principal_id), error)
                details['name'] = f"Group-{principal_id}"
        
        else:
            logger.warning(f"Unknown principal type: {principal_type}")
            details['name'] = f"{principal_type}-{principal_id}"
    
    except Exception as e:
        logger.error("Error getting principal details for %s %s: %s",
                     principal_type, redact_principal(principal_id), str(e))
        details['name'] = f"{principal_type}-{principal_id}"
    
    return details