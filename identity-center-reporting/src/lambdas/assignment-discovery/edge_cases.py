# Edge case handling for Assignment Discovery
# Handles assignments where users/groups no longer exist in Identity Provider

import logging
from typing import Dict, Any, Optional, List
from shared.utils import safe_api_call, redact_principal
from shared.models import Assignment

logger = logging.getLogger(__name__)

def handle_missing_principal(
    assignment_data: Dict[str, Any],
    application_arn: str,
    instance_arn: str,
    account_id: str,
    principal_type: str,
    principal_id: str
) -> Optional[Assignment]:
    """
    Handle assignments where users/groups no longer exist in Identity Provider
    
    Args:
        assignment_data: Original assignment data
        application_arn: Application ARN
        instance_arn: Instance ARN
        account_id: Account ID
        principal_type: Principal type (USER or GROUP)
        principal_id: Principal ID
    
    Returns:
        Assignment object with deleted principal marker or None
    """
    try:
        logger.warning("Principal %s (%s) not found in Identity Provider",
                       redact_principal(principal_id), principal_type)
        
        # Create a descriptive name for the deleted principal
        if principal_type == 'USER':
            principal_name = f"[DELETED USER] {principal_id}"
        elif principal_type == 'GROUP':
            principal_name = f"[DELETED GROUP] {principal_id}"
        else:
            principal_name = f"[DELETED {principal_type}] {principal_id}"
        
        # Create assignment ID
        assignment_id = Assignment.create_assignment_id(application_arn, principal_id)
        
        # Get permission set details if available
        permission_set_arn = assignment_data.get('PermissionSetArn')
        permission_set_name = None
        
        # Create Assignment object with deleted marker
        assignment = Assignment(
            assignment_id=assignment_id,
            application_arn=application_arn,
            principal_id=principal_id,
            principal_type=principal_type,
            principal_name=principal_name,
            permission_set_arn=permission_set_arn,
            permission_set_name=permission_set_name,
            account_id=account_id,
            instance_arn=instance_arn,
            assignment_status='INACTIVE'  # Mark as inactive for deleted principals
        )
        
        # Log the missing principal for audit purposes
        log_missing_principal(principal_type, principal_id, application_arn)
        
        return assignment
        
    except Exception as e:
        logger.error("Error handling missing principal %s: %s", redact_principal(principal_id), str(e))
        return None

def log_missing_principal(principal_type: str, principal_id: str, application_arn: str):
    """
    Log missing principals for audit and troubleshooting purposes
    
    Args:
        principal_type: Type of principal (USER or GROUP)
        principal_id: Principal ID
        application_arn: Application ARN
    """
    logger.warning(
        "MISSING_PRINCIPAL: %s %s assigned to %s but not found in Identity Provider. "
        "This may indicate a deleted user/group or synchronization issue with the "
        "identity source.",
        principal_type, redact_principal(principal_id), application_arn
    )

def get_permission_set_details_with_fallback(
    sso_client,
    instance_arn: str,
    permission_set_arn: Optional[str]
) -> Dict[str, Optional[str]]:
    """
    Get permission set details with fallback handling for missing permission sets
    
    Args:
        sso_client: SSO Admin client
        instance_arn: Instance ARN
        permission_set_arn: Permission set ARN (may be None)
    
    Returns:
        Dictionary with permission set name and policy information
    """
    result = {
        'permission_set_name': None,
        'policy_info': None
    }
    
    if not permission_set_arn:
        return result
    
    try:
        # Get permission set details
        success, ps_data, error = safe_api_call(
            lambda: sso_client.describe_permission_set(
                InstanceArn=instance_arn,
                PermissionSetArn=permission_set_arn
            ),
            f"Failed to describe permission set {permission_set_arn}",
            continue_on_error=True
        )
        
        if success:
            permission_set = ps_data.get('PermissionSet', {})
            result['permission_set_name'] = permission_set.get('Name')
            
            # Get basic policy information
            result['policy_info'] = get_permission_set_policy_info(
                sso_client, instance_arn, permission_set_arn
            )
        else:
            logger.warning(f"Could not retrieve permission set details: {error}")
            result['permission_set_name'] = f"[UNKNOWN] {permission_set_arn.split('/')[-1]}"
            
    except Exception as e:
        logger.warning(f"Error getting permission set details: {str(e)}")
        result['permission_set_name'] = f"[ERROR] {permission_set_arn.split('/')[-1]}"
    
    return result

def get_permission_set_policy_info(
    sso_client,
    instance_arn: str,
    permission_set_arn: str
) -> Optional[Dict[str, Any]]:
    """
    Get permission set policy information for audit purposes
    
    Args:
        sso_client: SSO Admin client
        instance_arn: Instance ARN
        permission_set_arn: Permission set ARN
    
    Returns:
        Dictionary with policy information or None
    """
    try:
        policy_info = {
            'has_inline_policy': False,
            'managed_policies': [],
            'customer_managed_policies': []
        }
        
        # Check for inline policy
        try:
            success, inline_policy, error = safe_api_call(
                lambda: sso_client.get_inline_policy_for_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                ),
                f"Failed to get inline policy for permission set {permission_set_arn}",
                continue_on_error=True
            )
            
            if success and inline_policy.get('InlinePolicy'):
                policy_info['has_inline_policy'] = True
        except Exception:
            pass  # Inline policy may not exist
        
        # Get managed policies
        try:
            success, managed_policies, error = safe_api_call(
                lambda: sso_client.list_managed_policies_in_permission_set(
                    InstanceArn=instance_arn,
                    PermissionSetArn=permission_set_arn
                ),
                f"Failed to list managed policies for permission set {permission_set_arn}",
                continue_on_error=True
            )
            
            if success:
                attached_policies = managed_policies.get('AttachedManagedPolicies', [])
                for policy in attached_policies:
                    policy_arn = policy.get('Arn', '')
                    if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                        policy_info['managed_policies'].append(policy.get('Name', policy_arn))
                    else:
                        policy_info['customer_managed_policies'].append(policy.get('Name', policy_arn))
        except Exception:
            pass  # Managed policies may not exist
        
        return policy_info if any([
            policy_info['has_inline_policy'],
            policy_info['managed_policies'],
            policy_info['customer_managed_policies']
        ]) else None
        
    except Exception as e:
        logger.debug(f"Error getting policy info for permission set {permission_set_arn}: {str(e)}")
        return None

def validate_assignment_consistency(
    assignments: List[Assignment],
    application_arn: str
) -> Dict[str, Any]:
    """
    Validate assignment consistency and detect potential issues
    
    Args:
        assignments: List of discovered assignments
        application_arn: Application ARN
    
    Returns:
        Dictionary with validation results and warnings
    """
    validation_result = {
        'total_assignments': len(assignments),
        'user_assignments': 0,
        'group_assignments': 0,
        'deleted_principals': 0,
        'missing_permission_sets': 0,
        'warnings': []
    }
    
    try:
        for assignment in assignments:
            # Count assignment types
            if assignment.principal_type == 'USER':
                validation_result['user_assignments'] += 1
            elif assignment.principal_type == 'GROUP':
                validation_result['group_assignments'] += 1
            
            # Count deleted principals
            if '[DELETED' in assignment.principal_name:
                validation_result['deleted_principals'] += 1
            
            # Count missing permission sets
            if not assignment.permission_set_arn:
                validation_result['missing_permission_sets'] += 1
        
        # Generate warnings based on validation
        if validation_result['deleted_principals'] > 0:
            validation_result['warnings'].append(
                f"Found {validation_result['deleted_principals']} assignments to deleted principals"
            )
        
        if validation_result['missing_permission_sets'] > 0:
            validation_result['warnings'].append(
                f"Found {validation_result['missing_permission_sets']} assignments without permission sets"
            )
        
        # Check for unusual patterns
        if validation_result['total_assignments'] == 0:
            validation_result['warnings'].append("No assignments found for application")
        
        if validation_result['user_assignments'] == 0 and validation_result['group_assignments'] == 0:
            validation_result['warnings'].append("No valid user or group assignments found")
        
        logger.info(f"Assignment validation for {application_arn}: {validation_result}")
        
    except Exception as e:
        logger.error(f"Error validating assignment consistency: {str(e)}")
        validation_result['warnings'].append(f"Validation error: {str(e)}")
    
    return validation_result