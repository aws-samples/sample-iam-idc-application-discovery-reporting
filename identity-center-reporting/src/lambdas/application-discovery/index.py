# Application Discovery Lambda Function
# Enumerates applications within IAM Identity Center instances

import json
import boto3
import logging
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from shared.utils import setup_logging, handle_api_error, handle_access_denied_exception, get_aws_client, paginate_api_call, safe_api_call, redact_principal
from shared.models import Application, Assignment, DiscoveryResult, ValidationError
from shared.tracing import (
    init_xray_tracing, trace_lambda_handler, trace_discovery_operation,
    trace_aws_api_call, add_discovery_metrics, trace_performance_bottleneck
)

# Initialize X-Ray tracing
init_xray_tracing("application-discovery")

logger = setup_logging(__name__)

@trace_lambda_handler
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for application discovery within IAM Identity Center instances
    
    Expected event format:
    {
        "instance_arn": "arn:aws:sso:::instance/ssoins-1234567890abcdef",
        "account_id": "123456789012",
        "region": "us-east-1",
        "role_arn": "arn:aws:iam::123456789012:role/CrossAccountRole" (optional)
    }
    """
    logger.info("Starting application discovery")
    
    try:
        # Extract required parameters from event
        instance_arn = event.get('instance_arn')
        account_id = event.get('account_id')
        region = event.get('region')
        
        # Extract role_arn from discovery_metadata if present
        discovery_metadata = event.get('discovery_metadata', {})
        role_arn = event.get('role_arn') or discovery_metadata.get('role_arn')
        
        if not instance_arn:
            raise ValueError("instance_arn is required")
        if not account_id:
            raise ValueError("account_id is required")
        if not region:
            raise ValueError("region is required")
        
        logger.info(f"Discovering applications for instance: {instance_arn}")
        if role_arn:
            logger.info(f"Using cross-account role: {role_arn}")
        
        # Discover applications
        discovery_result = discover_applications(instance_arn, account_id, region, role_arn)
        
        # Persist applications to DynamoDB
        if discovery_result.data:
            persistence_result = persist_applications_to_dynamodb(discovery_result.data)
            if not persistence_result.success:
                discovery_result.errors.extend(persistence_result.errors)
                discovery_result.success = False
        
        logger.info(f"Application discovery completed. Found {len(discovery_result.data)} applications")

        # Include role_arn in each application dict so assignment discovery
        # can use it for cross-account access
        applications_list = [app.to_dict() for app in discovery_result.data]
        if role_arn:
            for app in applications_list:
                app['role_arn'] = role_arn

        return {
            'success': discovery_result.success,
            'message': discovery_result.message,
            'applications': applications_list,
            'errors': discovery_result.errors,
            'count': len(discovery_result.data)
        }
    
    except boto3.exceptions.Boto3Error as e:
        # Handle AWS SDK errors including AccessDeniedException
        if hasattr(e, 'response') and e.response.get('Error', {}).get('Code') == 'AccessDeniedException':
            return handle_access_denied_exception(e, context, instance_arn)
        logger.error(f"Application discovery failed: {str(e)}")
        return handle_api_error(e)
        
    except Exception as e:
        logger.error(f"Application discovery failed: {str(e)}")
        return handle_api_error(e)

@trace_discovery_operation("application_discovery", {"component": "application-discovery"})
@trace_performance_bottleneck("application_discovery", 45.0)
def discover_applications(
    instance_arn: str, 
    account_id: str, 
    region: str, 
    role_arn: Optional[str] = None
) -> DiscoveryResult:
    """
    Discover applications within an IAM Identity Center instance
    
    Args:
        instance_arn: IAM Identity Center instance ARN
        account_id: AWS account ID
        region: AWS region
        role_arn: Optional cross-account role ARN
    
    Returns:
        DiscoveryResult containing discovered applications
    """
    result = DiscoveryResult()
    
    try:
        # Create SSO Admin client
        sso_client = get_aws_client('sso-admin', region, role_arn)
        
        logger.info(f"Listing applications for instance: {instance_arn}")
        
        # List applications using pagination
        success, applications_data, error = safe_api_call(
            lambda: paginate_api_call(
                sso_client, 
                'list_applications',
                InstanceArn=instance_arn
            ),
            f"Failed to list applications for instance {instance_arn}"
        )
        
        if not success:
            # Check if this is an AccessDeniedException
            if 'AccessDeniedException' in error or 'is not authorized to perform' in error:
                logger.error("=" * 80)
                logger.error("ACCESS DENIED: sso:ListApplications")
                logger.error("=" * 80)
                logger.error(f"Lambda Function: application-discovery")
                logger.error(f"Missing Permission: sso:ListApplications")
                logger.error(f"Resource ARN: {instance_arn}")
                logger.error(f"Error: {error}")
                logger.error("=" * 80)
            result.add_error(error)
            return result
        
        logger.info(f"Found {len(applications_data)} applications")
        
        # Process each application
        for app_data in applications_data:
            try:
                # Get detailed application information
                app_arn = app_data.get('ApplicationArn')
                if not app_arn:
                    logger.warning("Application missing ARN, skipping")
                    continue
                
                logger.debug(f"Processing application: {app_arn}")
                
                # Get application details
                detailed_app = get_application_details(sso_client, app_arn)
                if detailed_app:
                    # Create Application model instance
                    application = create_application_model(
                        detailed_app, 
                        instance_arn, 
                        account_id, 
                        region
                    )
                    
                    result.add_data(application)
                    logger.debug(f"Successfully processed application: {application.name}")
                else:
                    logger.warning(f"Failed to get details for application: {app_arn}")
                    
            except Exception as e:
                error_msg = f"Error processing application {app_data.get('ApplicationArn', 'unknown')}: {str(e)}"
                logger.warning(error_msg)
                result.add_error(error_msg)
                continue
        
        if result.errors:
            result.message = (
                f"Discovered {len(result.data)} applications with "
                f"{len(result.errors)} error(s)"
            )
        else:
            result.message = f"Successfully discovered {len(result.data)} applications"
        logger.info(result.message)
        
    except Exception as e:
        error_msg = f"Failed to discover applications: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result

@trace_aws_api_call("sso-admin", "describe_application")
def get_application_details(sso_client: boto3.client, application_arn: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed application configuration including provider details and certificates
    
    Args:
        sso_client: SSO Admin client
        application_arn: Application ARN
    
    Returns:
        Application details dictionary or None if failed
    """
    success, app_details, error = safe_api_call(
        lambda: sso_client.describe_application(ApplicationArn=application_arn),
        f"Failed to describe application {application_arn}"
    )
    
    if not success:
        logger.warning(error)
        return None
    
    # Enhance application details with additional configuration
    enhanced_details = app_details.copy()
    
    # Get application provider details if available
    provider_arn = app_details.get('ApplicationProviderArn')
    if provider_arn:
        provider_details = get_application_provider_details(sso_client, provider_arn)
        if provider_details:
            enhanced_details['ProviderDetails'] = provider_details
    
    # Get application assignments metadata (count only, not full assignments)
    assignment_metadata = get_application_assignment_metadata(sso_client, application_arn)
    if assignment_metadata:
        enhanced_details['AssignmentMetadata'] = assignment_metadata
    
    return enhanced_details

def get_application_provider_details(sso_client: boto3.client, provider_arn: str) -> Optional[Dict[str, Any]]:
    """
    Get application provider details including supported configurations
    
    Args:
        sso_client: SSO Admin client
        provider_arn: Application provider ARN
    
    Returns:
        Provider details dictionary or None if failed
    """
    try:
        success, provider_details, error = safe_api_call(
            lambda: sso_client.describe_application_provider(ApplicationProviderArn=provider_arn),
            f"Failed to describe application provider {provider_arn}",
            continue_on_error=True
        )
        
        if success:
            return {
                'DisplayName': provider_details.get('DisplayName'),
                'FederationProtocol': provider_details.get('FederationProtocol'),
                'ResourceServerConfig': provider_details.get('ResourceServerConfig'),
                'ApplicationProviderArn': provider_arn
            }
        else:
            logger.debug(f"Could not get provider details: {error}")
            return None
            
    except Exception as e:
        logger.debug(f"Error getting provider details for {provider_arn}: {str(e)}")
        return None

def get_application_assignment_metadata(sso_client: boto3.client, application_arn: str) -> Optional[Dict[str, Any]]:
    """
    Get application assignment metadata (counts and summary info)
    
    Args:
        sso_client: SSO Admin client
        application_arn: Application ARN
    
    Returns:
        Assignment metadata dictionary or None if failed
    """
    try:
        # Get a limited list of assignments to determine if any exist
        success, assignments, error = safe_api_call(
            lambda: sso_client.list_application_assignments(
                ApplicationArn=application_arn,
                MaxResults=1  # Just check if any assignments exist
            ),
            f"Failed to check assignments for application {application_arn}",
            continue_on_error=True
        )
        
        if success:
            has_assignments = len(assignments.get('ApplicationAssignments', [])) > 0
            return {
                'HasAssignments': has_assignments,
                'CheckedAt': datetime.now(timezone.utc).isoformat()
            }
        else:
            logger.debug(f"Could not check assignments: {error}")
            return None
            
    except Exception as e:
        logger.debug(f"Error checking assignments for {application_arn}: {str(e)}")
        return None

def create_application_model(
    app_data: Dict[str, Any], 
    instance_arn: str, 
    account_id: str, 
    region: str
) -> Application:
    """
    Create Application model from AWS API response with enhanced configuration details
    
    Args:
        app_data: Application data from AWS API
        instance_arn: IAM Identity Center instance ARN
        account_id: AWS account ID
        region: AWS region
    
    Returns:
        Application model instance
    """
    # Extract application details
    application_arn = app_data.get('ApplicationArn')
    name = app_data.get('Name', 'Unknown Application')
    description = app_data.get('Description')
    status = app_data.get('Status', 'ENABLED')
    
    # Extract provider information
    application_provider_arn = app_data.get('ApplicationProviderArn')
    
    # Extract and enhance portal options with additional configuration
    portal_options = extract_portal_configuration(app_data)
    
    # Extract timestamps
    created_date = None
    if 'CreatedDate' in app_data:
        raw_created_date = app_data['CreatedDate']
        if isinstance(raw_created_date, str):
            # Remove extra 'Z' if it exists after timezone offset (handles microseconds)
            if '+00:00Z' in raw_created_date:
                created_date = raw_created_date.replace('+00:00Z', '+00:00')
            else:
                created_date = raw_created_date
        else:
            # If it's a datetime object, convert to ISO format
            created_date = raw_created_date.isoformat() + 'Z'
    
    # Create Application instance
    application = Application(
        application_arn=application_arn,
        instance_arn=instance_arn,
        name=name,
        description=description,
        status=status,
        application_provider_arn=application_provider_arn,
        account_id=account_id,
        region=region,
        portal_options=portal_options,
        created_date=created_date
    )
    
    return application

def extract_portal_configuration(app_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract and enhance portal configuration including relay state and certificate info
    
    Args:
        app_data: Application data from AWS API
    
    Returns:
        Enhanced portal options dictionary
    """
    portal_options = app_data.get('PortalOptions', {})
    
    if not portal_options:
        return None
    
    enhanced_options = portal_options.copy()
    
    # Add application type identification
    enhanced_options['ApplicationType'] = identify_application_type(app_data)
    
    # Extract sign-in configuration details
    sign_in_options = portal_options.get('SignInOptions', {})
    if sign_in_options:
        enhanced_sign_in = sign_in_options.copy()
        
        # Extract relay state information for SAML applications
        if sign_in_options.get('Origin') == 'APPLICATION':
            app_url = sign_in_options.get('ApplicationUrl')
            if app_url:
                enhanced_sign_in['RelayStateInfo'] = {
                    'ApplicationUrl': app_url,
                    'HasCustomUrl': True
                }
        
        enhanced_options['SignInOptions'] = enhanced_sign_in
    
    # Add provider details if available
    provider_details = app_data.get('ProviderDetails')
    if provider_details:
        enhanced_options['ProviderDetails'] = provider_details
    
    # Add certificate information for SAML applications
    if enhanced_options.get('ApplicationType') == 'SAML':
        cert_info = extract_certificate_information(app_data)
        if cert_info:
            enhanced_options['CertificateInfo'] = cert_info
    
    # Add assignment metadata
    assignment_metadata = app_data.get('AssignmentMetadata')
    if assignment_metadata:
        enhanced_options['AssignmentMetadata'] = assignment_metadata
    
    return enhanced_options

def extract_certificate_information(app_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Extract certificate information for SAML applications
    
    Args:
        app_data: Application data from AWS API
    
    Returns:
        Certificate information dictionary or None
    """
    try:
        # Look for certificate information in various places
        cert_info = {}
        
        provider_details = app_data.get('ProviderDetails', {})
        if provider_details.get('FederationProtocol') == 'SAML':
            # Only the federation protocol is reported. Certificate presence is
            # deliberately NOT asserted: the Identity Center application APIs do
            # not expose certificate material, so any HasCertificate value here
            # would be a guess -- and a false positive in a compliance review.
            cert_info['FederationProtocol'] = 'SAML'
        
        return cert_info if cert_info else None
        
    except Exception as e:
        logger.debug(f"Error extracting certificate information: {str(e)}")
        return None

def persist_applications_to_dynamodb(applications: List[Application]) -> DiscoveryResult:
    """
    Persist discovered applications to DynamoDB with validation and upsert logic
    
    Args:
        applications: List of Application objects to persist
    
    Returns:
        DiscoveryResult indicating success/failure of persistence operations
    """
    result = DiscoveryResult()
    
    try:
        # Get DynamoDB table name from environment
        table_name = os.environ.get('APPLICATIONS_TABLE')
        if not table_name:
            error_msg = "APPLICATIONS_TABLE environment variable not set"
            logger.error(error_msg)
            result.add_error(error_msg)
            return result
        
        # Create DynamoDB client
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)
        
        logger.info(f"Persisting {len(applications)} applications to DynamoDB table: {table_name}")
        
        # Process applications in batches for better performance
        batch_size = 25  # DynamoDB batch write limit
        for i in range(0, len(applications), batch_size):
            batch = applications[i:i + batch_size]
            batch_result = persist_application_batch(table, batch)
            
            if not batch_result.success:
                result.errors.extend(batch_result.errors)
                result.success = False
            else:
                result.data.extend(batch_result.data)
        
        if result.success:
            result.message = f"Successfully persisted {len(result.data)} applications to DynamoDB"
            logger.info(result.message)
        else:
            result.message = f"Persistence completed with errors. {len(result.data)} successful, {len(result.errors)} errors"
            logger.warning(result.message)
        
    except Exception as e:
        error_msg = f"Failed to persist applications to DynamoDB: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result

def persist_application_batch(table: boto3.resource, applications: List[Application]) -> DiscoveryResult:
    """
    Persist a batch of applications to DynamoDB
    
    Args:
        table: DynamoDB table resource
        applications: List of Application objects to persist
    
    Returns:
        DiscoveryResult for the batch operation
    """
    result = DiscoveryResult()
    
    try:
        # Prepare batch write items
        with table.batch_writer() as batch:
            for application in applications:
                try:
                    # Validate application before writing
                    application.validate()
                    
                    # Convert to DynamoDB item format
                    item = prepare_application_item(application)
                    
                    # Write to DynamoDB with upsert logic
                    batch.put_item(Item=item)
                    result.add_data(application)
                    
                    logger.debug(f"Queued application for batch write: {application.name}")
                    
                except ValidationError as e:
                    error_msg = f"Validation failed for application {application.application_arn}: {str(e)}"
                    logger.warning(error_msg)
                    result.add_error(error_msg)
                    continue
                    
                except Exception as e:
                    error_msg = f"Error preparing application {application.application_arn} for write: {str(e)}"
                    logger.warning(error_msg)
                    result.add_error(error_msg)
                    continue
        
        logger.info(f"Batch write completed for {len(result.data)} applications")
        
    except Exception as e:
        error_msg = f"Batch write failed: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result

def prepare_application_item(application: Application) -> Dict[str, Any]:
    """
    Prepare application data for DynamoDB storage with proper formatting
    
    Args:
        application: Application object to prepare
    
    Returns:
        Dictionary formatted for DynamoDB storage
    """
    # Start with the application's dictionary representation
    item = application.to_dict()
    
    # Ensure required fields are present
    if not item.get('last_updated'):
        item['last_updated'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    
    # Add discovery metadata
    item['discovery_metadata'] = {
        'discovered_by': 'application-discovery-lambda',
        'discovery_timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'version': '1.0'
    }
    
    # Handle nested objects (convert to JSON strings if needed)
    if item.get('portal_options') and isinstance(item['portal_options'], dict):
        # Keep as dict - DynamoDB supports nested objects
        pass
    
    # Remove None values to save space
    item = {k: v for k, v in item.items() if v is not None}
    
    return item

def check_existing_application(table: boto3.resource, application_arn: str, instance_arn: str) -> Optional[Dict[str, Any]]:
    """
    Check if an application already exists in DynamoDB
    
    Args:
        table: DynamoDB table resource
        application_arn: Application ARN (primary key)
        instance_arn: Instance ARN (sort key)
    
    Returns:
        Existing item dictionary or None if not found
    """
    try:
        response = table.get_item(
            Key={
                'application_arn': application_arn,
                'instance_arn': instance_arn
            }
        )
        return response.get('Item')
        
    except Exception as e:
        logger.debug(f"Error checking existing application {application_arn}: {str(e)}")
        return None

def should_update_application(existing_item: Dict[str, Any], new_application: Application) -> bool:
    """
    Determine if an existing application should be updated based on change detection
    
    Args:
        existing_item: Existing DynamoDB item
        new_application: New application data
    
    Returns:
        True if update is needed, False otherwise
    """
    try:
        # Compare key fields that indicate changes
        new_item = new_application.to_dict()
        
        # Fields to compare for changes
        compare_fields = ['name', 'description', 'status', 'application_provider_arn']
        
        for field in compare_fields:
            existing_value = existing_item.get(field)
            new_value = new_item.get(field)
            
            if existing_value != new_value:
                logger.debug(f"Change detected in field '{field}': {existing_value} -> {new_value}")
                return True
        
        # Check portal options for changes
        existing_portal = existing_item.get('portal_options', {})
        new_portal = new_item.get('portal_options', {})
        
        if existing_portal != new_portal:
            logger.debug("Change detected in portal_options")
            return True
        
        return False
        
    except Exception as e:
        logger.debug(f"Error comparing applications, defaulting to update: {str(e)}")
        return True  # Default to update on error

def identify_application_type(app_data: Dict[str, Any]) -> str:
    """
    Identify application type (SAML, OAuth, AWS managed)
    
    Args:
        app_data: Application data from AWS API
    
    Returns:
        Application type string
    """
    provider_arn = app_data.get('ApplicationProviderArn', '')
    
    # AWS managed applications
    if provider_arn.startswith('arn:aws:sso::aws:applicationProvider/'):
        return 'AWS_MANAGED'
    
    # Check for SAML configuration
    portal_options = app_data.get('PortalOptions', {})
    sign_in_options = portal_options.get('SignInOptions', {})
    
    if sign_in_options.get('Origin') == 'APPLICATION':
        # Likely SAML if it has an application URL
        if sign_in_options.get('ApplicationUrl'):
            return 'SAML'
    
    # Default to OAuth for custom applications
    if not provider_arn or provider_arn.startswith('arn:aws:sso::'):
        return 'OAUTH'
    
    return 'UNKNOWN'
@trace_aws_api_call("sso-admin", "list_application_assignments")
def discover_application_assignments(
    sso_client: boto3.client, 
    application_arn: str,
    instance_arn: str
) -> List[Assignment]:
    """
    Discover assignments (users and groups) for a specific application
    
    Args:
        sso_client: SSO Admin client
        application_arn: ARN of the application
        instance_arn: ARN of the SSO instance
    
    Returns:
        List of Assignment model objects
    """
    assignments = []
    
    try:
        logger.info(f"Discovering assignments for application: {application_arn}")
        
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
            # Check if this is an AccessDeniedException
            if 'AccessDeniedException' in error or 'is not authorized to perform' in error:
                logger.error("=" * 80)
                logger.error("ACCESS DENIED: sso:ListApplicationAssignments")
                logger.error("=" * 80)
                logger.error(f"Lambda Function: application-discovery")
                logger.error(f"Missing Permission: sso:ListApplicationAssignments")
                logger.error(f"Resource ARN: {application_arn}")
                logger.error(f"Error: {error}")
                logger.error("=" * 80)
            logger.warning(f"Could not list assignments for application {application_arn}: {error}")
            return assignments
        
        logger.info(f"Found {len(assignments_data)} assignments for application")
        
        # Get identity store ID from instance
        identity_store_id = get_identity_store_id_from_instance(sso_client, instance_arn)
        if not identity_store_id:
            logger.warning(f"Could not get identity store ID for instance {instance_arn}")
            return assignments
        
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
                
                # Create Assignment model object with enhanced metadata
                assignment_obj = Assignment(
                    assignment_id=assignment_id,
                    application_arn=application_arn,
                    principal_id=principal_id,
                    principal_type=principal_type,
                    principal_name=principal_details.get('name', f'{principal_type}-{principal_id}'),
                    instance_arn=instance_arn,
                    assignment_status='ACTIVE',
                    last_updated=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    # Enhanced metadata
                    principal_display_name=principal_details.get('display_name'),
                    principal_email=principal_details.get('email'),
                    name_resolved=principal_details.get('resolved', False),
                    resolution_error=None if principal_details.get('resolved', False) else f"Could not resolve {principal_type} name"
                )
                
                assignments.append(assignment_obj)
                logger.debug("Added assignment: %s %s", principal_type,
                             redact_principal(principal_details.get('name', principal_id)))
                
            except Exception as e:
                logger.error(f"Error processing assignment {assignment}: {str(e)}")
                continue
        
        logger.info(f"Successfully processed {len(assignments)} assignments")
        
    except Exception as e:
        logger.error(f"Error discovering assignments for application {application_arn}: {str(e)}")
    
    return assignments

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
            # Check if this is an AccessDeniedException
            if 'AccessDeniedException' in error or 'is not authorized to perform' in error:
                logger.error("=" * 80)
                logger.error("ACCESS DENIED: sso:DescribeInstance")
                logger.error("=" * 80)
                logger.error(f"Lambda Function: application-discovery")
                logger.error(f"Missing Permission: sso:DescribeInstance")
                logger.error(f"Resource ARN: {instance_arn}")
                logger.error(f"Error: {error}")
                logger.error("=" * 80)
            logger.warning(f"Could not describe instance {instance_arn}: {error}")
            return None
            
    except Exception as e:
        logger.error(f"Error getting identity store ID for instance {instance_arn}: {str(e)}")
        return None

@trace_aws_api_call("identitystore", "describe_principal")
def get_principal_details(
    identity_store_id: str, 
    principal_id: str, 
    principal_type: str
) -> Dict[str, Any]:
    """
    Get details for a principal (user or group) from the identity store with enhanced error handling
    
    Args:
        identity_store_id: ID of the identity store
        principal_id: ID of the principal
        principal_type: Type of principal ('USER' or 'GROUP')
    
    Returns:
        Dictionary with principal details including fallback names
    """
    details = {
        'name': f'{principal_type}-{principal_id}',  # Fallback name
        'display_name': None,
        'email': None,
        'resolved': False
    }
    
    if not identity_store_id or not principal_id or not principal_type:
        logger.warning(
            "Missing required parameters for principal resolution: "
            "store_id_present=%s, principal_id=%s, type=%s",
            bool(identity_store_id), redact_principal(principal_id), principal_type
        )
        return details
    
    try:
        # Create identity store client with retry configuration
        identity_client = get_aws_client('identitystore')
        
        if principal_type.upper() == 'USER':
            details.update(_resolve_user_details(identity_client, identity_store_id, principal_id))
        elif principal_type.upper() == 'GROUP':
            details.update(_resolve_group_details(identity_client, identity_store_id, principal_id))
        else:
            logger.warning(f"Unknown principal type: {principal_type}")
            details['name'] = f"Unknown-{principal_type}-{principal_id}"
    
    except Exception as e:
        logger.error("Unexpected error resolving principal %s %s: %s",
                     principal_type, redact_principal(principal_id), str(e))
        details['name'] = f"Error-{principal_type}-{principal_id}"
    
    return details

def _resolve_user_details(identity_client, identity_store_id: str, user_id: str) -> Dict[str, Any]:
    """Resolve user details with robust error handling"""
    details = {'resolved': False}
    
    def _describe_user():
        return identity_client.describe_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id
        )
    
    success, result, error = safe_api_call(
        _describe_user,
        f"Failed to describe user {user_id}",
        continue_on_error=True
    )
    
    if success and result:
        user_data = result
        
        # Extract user name with multiple fallbacks
        user_name = (
            user_data.get('UserName') or 
            user_data.get('DisplayName') or 
            user_data.get('Name', {}).get('FamilyName', '') + ', ' + user_data.get('Name', {}).get('GivenName', '') or
            f"User-{user_id}"
        ).strip(', ')
        
        details.update({
            'name': user_name,
            'display_name': user_data.get('DisplayName'),
            'resolved': True
        })
        
        # Extract primary email with fallback
        emails = user_data.get('Emails', [])
        primary_email = None
        
        # Look for primary email first
        for email in emails:
            if email.get('Primary', False):
                primary_email = email.get('Value')
                break
        
        # If no primary email, take the first available
        if not primary_email and emails:
            primary_email = emails[0].get('Value')
        
        details['email'] = primary_email
        
        logger.debug(f"Successfully resolved user: {user_name}")
    else:
        logger.warning(f"Could not resolve user {user_id}: {error}")
        details.update({
            'name': f"User-{user_id}",
            'resolved': False
        })
    
    return details

def _resolve_group_details(identity_client, identity_store_id: str, group_id: str) -> Dict[str, Any]:
    """Resolve group details with robust error handling"""
    details = {'resolved': False}
    
    def _describe_group():
        return identity_client.describe_group(
            IdentityStoreId=identity_store_id,
            GroupId=group_id
        )
    
    success, result, error = safe_api_call(
        _describe_group,
        f"Failed to describe group {group_id}",
        continue_on_error=True
    )
    
    if success and result:
        group_data = result
        
        # Extract group name with fallbacks
        group_name = (
            group_data.get('DisplayName') or 
            group_data.get('GroupName') or 
            f"Group-{group_id}"
        )
        
        details.update({
            'name': group_name,
            'display_name': group_data.get('DisplayName'),
            'resolved': True
        })
        
        logger.debug(f"Successfully resolved group: {group_name}")
    else:
        logger.warning(f"Could not resolve group {group_id}: {error}")
        details.update({
            'name': f"Group-{group_id}",
            'resolved': False
        })
    
    return details