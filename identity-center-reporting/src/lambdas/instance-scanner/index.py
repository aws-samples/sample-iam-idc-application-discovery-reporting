# Instance Scanner Lambda Function
# Unified scanner that discovers ALL IAM Identity Center instances
# (both organization-level and account-level) in a single execution
#
# This Lambda function:
# 1. Discovers organization-level instances in the management account
# 2. Discovers account-level instances across all member accounts
# 3. Persists all discovered instances to DynamoDB
# 4. Returns combined results for downstream processing

import json
import boto3
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from botocore.exceptions import ClientError, BotoCoreError
from shared.utils import setup_logging, handle_api_error, handle_access_denied_exception, get_aws_client, paginate_api_call, safe_api_call
from shared.models import Instance, InstanceType, DiscoveryResult
from shared.alerting import (
    alert_manager, send_discovery_failure_alert, track_discovery_metrics,
    AlertType, AlertSeverity
)
from shared.tracing import (
    init_xray_tracing, trace_lambda_handler, trace_discovery_operation,
    trace_aws_api_call, add_discovery_metrics, trace_performance_bottleneck
)

# Initialize X-Ray tracing
init_xray_tracing("instance-scanner")

logger = setup_logging(__name__)



@trace_lambda_handler
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for comprehensive IAM Identity Center instance discovery.
    Discovers both organization-level and account-level instances.
    """
    logger.info("Starting unified instance scanner")
    
    # Get discovery run ID from event or generate one
    discovery_run_id = event.get('discovery_run_id', f"instance-scan-{int(datetime.now(timezone.utc).timestamp())}")
    logger.info(f"Discovery run ID: {discovery_run_id}")
    
    # Send discovery status notification
    alert_manager.send_discovery_status(
        status="started",
        discovery_run_id=discovery_run_id,
        details={"component": "instance-scanner", "trigger": event.get('trigger', 'unknown')}
    )
    
    try:
        # Discover ALL instances (both org and account level)
        result = discover_all_instances_comprehensive(discovery_run_id)
        
        # Track discovery metrics
        track_discovery_metrics(
            discovery_run_id=discovery_run_id,
            component="instance-scanner",
            accounts_processed=result.metadata.get('accounts_scanned', 0),
            applications_found=0,  # This scanner doesn't find applications
            assignments_found=0,   # This scanner doesn't find assignments
            errors_encountered=len(result.errors)
        )
        
        if result.success:
            logger.info(f"Instance scanner completed successfully. Found {len(result.data)} total instances")
            
            # Send success notification
            alert_manager.send_discovery_status(
                status="completed",
                discovery_run_id=discovery_run_id,
                details={
                    "component": "instance-scanner",
                    "instances_found": len(result.data),
                    "org_instances": result.metadata.get('org_instances_count', 0),
                    "account_instances": result.metadata.get('account_instances_count', 0),
                    "errors": len(result.errors)
                }
            )
        else:
            logger.error(f"Instance scanner completed with errors: {result.errors}")
            
            # Send failure alert
            send_discovery_failure_alert(
                component="instance-scanner",
                error="; ".join(result.errors),
                discovery_run_id=discovery_run_id
            )
        
        response_data = {
            'success': result.success,
            'message': result.message,
            'instances': [instance.to_dict() for instance in result.data],
            'errors': result.errors,
            'discovery_run_id': discovery_run_id,
            'timestamp': result.timestamp,
            'metadata': result.metadata
        }
        
        return response_data
    
    except ClientError as e:
        # Handle AWS SDK errors including AccessDeniedException
        if e.response.get('Error', {}).get('Code') == 'AccessDeniedException':
            return handle_access_denied_exception(e, context, None)
        logger.error(f"Instance scanner failed: {str(e)}")
        
        # Send critical failure alert
        send_discovery_failure_alert(
            component="instance-scanner",
            error=str(e),
            discovery_run_id=discovery_run_id
        )
        
        return handle_api_error(e)
        
    except Exception as e:
        logger.error(f"Instance scanner failed: {str(e)}")
        
        # Send critical failure alert
        send_discovery_failure_alert(
            component="instance-scanner",
            error=str(e),
            discovery_run_id=discovery_run_id
        )
        
        return handle_api_error(e)

@trace_discovery_operation("comprehensive_instance_discovery", {"component": "instance-scanner"})
@trace_performance_bottleneck("comprehensive_instance_discovery", 90.0)
def discover_all_instances_comprehensive(discovery_run_id: str) -> DiscoveryResult:
    """
    Discover ALL IAM Identity Center instances (organization and account level).
    
    This function:
    1. Discovers organization-level instances in the management account
    2. Discovers account-level instances across all member accounts
    3. Combines and deduplicates results
    
    Args:
        discovery_run_id: Unique identifier for this discovery run
    
    Returns:
        DiscoveryResult containing all discovered instances
    """
    result = DiscoveryResult()
    result.metadata = {
        'org_instances_count': 0,
        'account_instances_count': 0,
        'accounts_scanned': 0,
        'accounts_with_role_access': 0,
        'accounts_without_role': 0
    }
    
    try:
        # Get AWS Organizations client
        org_client = get_aws_client('organizations')
        
        # Get organization information
        org_info = get_organization_info(org_client)
        if org_info:
            logger.info(f"Scanning organization: {org_info.get('Id', 'Unknown')}")
        
        # Get all accounts in the organization
        accounts = get_organization_accounts(org_client)
        logger.info(f"Found {len(accounts)} accounts in organization")
        
        # Get current account
        sts_client = get_aws_client('sts')
        current_account = sts_client.get_caller_identity()['Account']

        # Get credentials for delegated admin (None if using current account)
        delegated_admin_credentials = get_delegated_admin_credentials(current_account)

        # Get all enabled regions (used by both org and account discovery)
        all_regions = get_sso_enabled_regions()
        logger.info(f"Will scan {len(all_regions)} regions for instance discovery")

        # Step 1: Discover organization-level instances across ALL regions
        logger.info("=" * 60)
        logger.info("STEP 1: Discovering organization-level instances (all regions)")
        logger.info("=" * 60)

        org_instances = discover_organization_level_instances(
            delegated_admin_credentials,
            current_account,
            discovery_run_id,
            all_regions
        )
        
        for instance in org_instances:
            result.add_data(instance)
        
        result.metadata['org_instances_count'] = len(org_instances)
        logger.info(f"Found {len(org_instances)} organization-level instances")
        
        # Step 2: Discover account-level instances across member accounts
        logger.info("=" * 60)
        logger.info("STEP 2: Discovering account-level instances")
        logger.info("=" * 60)
        
        # Pass org-level instance ARNs so they are excluded from the account-level scan
        org_instance_arns = {inst.instance_arn for inst in org_instances}

        account_instances, account_stats = discover_account_level_instances(
            accounts,
            current_account,
            discovery_run_id,
            all_regions,
            org_instance_arns
        )
        
        for instance in account_instances:
            result.add_data(instance)
        
        result.metadata['account_instances_count'] = len(account_instances)
        result.metadata.update(account_stats)
        logger.info(f"Found {len(account_instances)} account-level instances")
        
        # Persist all instances to DynamoDB
        if result.data:
            persist_instances_to_dynamodb(result.data, discovery_run_id)
            result.message = (
                f"Successfully discovered and persisted {len(result.data)} instances: "
                f"{len(org_instances)} organization-level, "
                f"{len(account_instances)} account-level"
            )
        else:
            result.message = "No IAM Identity Center instances found"
        
        logger.info("=" * 60)
        logger.info("DISCOVERY SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total instances found: {len(result.data)}")
        logger.info(f"  Organization-level: {len(org_instances)}")
        logger.info(f"  Account-level: {len(account_instances)}")
        logger.info(f"Accounts scanned: {result.metadata['accounts_scanned']}")
        logger.info(f"  With role access: {result.metadata['accounts_with_role_access']}")
        logger.info(f"  Without role: {result.metadata['accounts_without_role']}")
        logger.info("=" * 60)
            
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = f"AWS API error during instance discovery: {error_code} - {e.response['Error']['Message']}"
        logger.error(error_msg)
        result.add_error(error_msg)
    except Exception as e:
        error_msg = f"Unexpected error during instance discovery: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result

def get_delegated_admin_credentials(current_account: str) -> Optional[Dict[str, str]]:
    """
    Get temporary credentials for the delegated admin account.

    Returns None if the current account's credentials should be used directly
    (i.e. no delegated admin configured, or already in the delegated admin account).
    Returns an STS credentials dict if cross-account role assumption was needed.

    Args:
        current_account: Current AWS account ID

    Returns:
        STS credentials dict (AccessKeyId, SecretAccessKey, SessionToken) or None
    """
    import os

    delegated_admin_account = os.environ.get('DELEGATED_ADMIN_ACCOUNT_ID')

    if not delegated_admin_account:
        logger.info("No delegated admin account configured, using current account credentials")
        return None

    if current_account == delegated_admin_account:
        logger.info(f"Already in delegated admin account {delegated_admin_account}, using current credentials")
        return None

    logger.info(f"Current account {current_account} is not delegated admin account {delegated_admin_account}")
    logger.info(f"Assuming cross-account role in delegated admin account")

    CROSS_ACCOUNT_ROLE_NAME = "iam-identity-center-cross-account-discovery-role"
    EXTERNAL_ID = "iam-identity-center-discovery"

    role_arn = f"arn:aws:iam::{delegated_admin_account}:role/{CROSS_ACCOUNT_ROLE_NAME}"

    try:
        sts_client = get_aws_client('sts')
        assume_response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"IAMIdentityCenterDiscovery-DelegatedAdmin",
            ExternalId=EXTERNAL_ID,
            DurationSeconds=3600
        )

        credentials = assume_response['Credentials']
        logger.info(f"Successfully assumed role in delegated admin account {delegated_admin_account}")
        return credentials

    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        logger.error(f"Failed to assume role in delegated admin account {delegated_admin_account}: {error_code}")
        logger.error(f"Role ARN: {role_arn}")
        logger.error(f"Ensure the cross-account role is deployed in the delegated admin account")
        raise


def create_sso_client_for_region(region: str, credentials: Optional[Dict[str, str]] = None) -> boto3.client:
    """
    Create a region-specific SSO Admin client.

    Args:
        region: AWS region name
        credentials: Optional STS credentials for cross-account access

    Returns:
        boto3 SSO Admin client for the specified region
    """
    if credentials:
        return boto3.client(
            'sso-admin',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
    else:
        return boto3.client('sso-admin', region_name=region)


@trace_aws_api_call("sso-admin", "list_instances")
def discover_organization_level_instances(
    credentials: Optional[Dict[str, str]],
    current_account: str,
    discovery_run_id: str,
    regions: List[str]
) -> List[Instance]:
    """
    Discover organization-level IAM Identity Center instances across all regions.

    Organization-level instances are bound to a specific region, so we must
    call ListInstances in every enabled region to find them all.

    Args:
        credentials: STS credentials for delegated admin, or None for current account
        current_account: Current AWS account ID
        discovery_run_id: Unique identifier for this discovery run
        regions: List of AWS regions to scan

    Returns:
        List of organization-level Instance objects
    """
    instances = []
    seen_instance_arns = set()

    logger.info(f"Scanning {len(regions)} regions for organization-level instances")

    for region in regions:
        try:
            sso_client = create_sso_client_for_region(region, credentials)

            def _list_instances(client=sso_client):
                all_instances = []
                next_token = None
                while True:
                    params = {}
                    if next_token:
                        params['NextToken'] = next_token
                    response = client.list_instances(**params)
                    all_instances.extend(response.get('Instances', []))
                    next_token = response.get('NextToken')
                    if not next_token:
                        break
                return all_instances

            success, instance_list, error = safe_api_call(
                _list_instances,
                f"Listing SSO instances in {region} for organization-level discovery",
                continue_on_error=True
            )

            if not success:
                if 'AccessDeniedException' in str(error) or 'is not authorized to perform' in str(error):
                    logger.debug(f"SSO not accessible in {region}")
                else:
                    # Not an expected absence -- throttling, expired credentials or a
                    # network error drops this entire region from the report, so it is
                    # surfaced rather than hidden at debug while the logger sits at INFO.
                    logger.warning(f"Region {region} skipped, instances not listed: {error}")
                continue

            # Filter for organization-level instances (not owned by current account)
            for instance_data in instance_list:
                try:
                    instance_arn = instance_data.get('InstanceArn')
                    owner_account_id = instance_data.get('OwnerAccountId')

                    if not instance_arn:
                        continue

                    # Skip account-level instances (owned by current account)
                    if owner_account_id == current_account:
                        continue

                    # Deduplicate across regions
                    if instance_arn in seen_instance_arns:
                        continue
                    seen_instance_arns.add(instance_arn)

                    identity_store_id = instance_data.get('IdentityStoreId')
                    status = instance_data.get('Status', 'ACTIVE')
                    created_date = instance_data.get('CreatedDate')

                    instance = create_instance_object(
                        instance_arn=instance_arn,
                        owner_account_id=owner_account_id,
                        region=region,
                        instance_type=InstanceType.ORGANIZATION.value,
                        status=status,
                        identity_store_id=identity_store_id,
                        created_date=created_date,
                        discovery_run_id=discovery_run_id,
                        discovered_by="instance-scanner",
                        discovery_method="list_instances_org_multi_region"
                    )

                    instances.append(instance)
                    logger.info(f"Discovered organization-level instance in {region}: {instance_arn}")

                except Exception as e:
                    logger.error(f"Error processing instance {instance_data.get('InstanceArn', 'Unknown')}: {str(e)}")
                    continue

        except Exception as e:
            logger.warning(f"Region {region} skipped for org instances: {str(e)}")
            continue

    logger.info(f"Organization-level scan complete: found {len(instances)} instances across {len(regions)} regions")
    return instances

def get_sso_enabled_regions() -> List[str]:
    """
    Get all AWS regions where IAM Identity Center (SSO) may be available.

    Uses EC2 DescribeRegions to dynamically discover all enabled regions.
    Raises on failure rather than falling back to a hardcoded list that
    could go stale as AWS adds new regions.

    Returns:
        List of AWS region names

    Raises:
        RuntimeError: If region discovery fails
    """
    ec2_client = boto3.client('ec2')
    response = ec2_client.describe_regions(
        Filters=[{
            'Name': 'opt-in-status',
            'Values': ['opt-in-not-required', 'opted-in']
        }]
    )
    regions = [r['RegionName'] for r in response.get('Regions', [])]

    if not regions:
        raise RuntimeError("EC2 DescribeRegions returned no enabled regions")

    logger.info(f"Dynamically discovered {len(regions)} enabled regions")
    return regions


def discover_account_level_instances(
    accounts: List[Dict[str, Any]],
    current_account: str,
    discovery_run_id: str,
    sso_regions: List[str],
    org_instance_arns: set = None
) -> tuple[List[Instance], Dict[str, int]]:
    """
    Discover account-level IAM Identity Center instances across member accounts.

    Account-level instances are regional resources, so each account must be
    scanned in every enabled AWS region. Organization-level instances are
    global and handled separately by discover_organization_level_instances.

    Args:
        accounts: List of account information dictionaries
        current_account: Current AWS account ID
        discovery_run_id: Unique identifier for this discovery run
        sso_regions: List of AWS regions to scan

    Returns:
        Tuple of (list of Instance objects, statistics dictionary)
    """
    instances = []
    seen_instance_arns = set(org_instance_arns or ())  # Pre-seed with org-level ARNs to skip
    stats = {
        'accounts_scanned': 0,
        'accounts_with_role_access': 0,
        'accounts_without_role': 0,
        'regions_scanned': 0,
        'regions_with_instances': 0
    }

    # Cross-account role configuration
    CROSS_ACCOUNT_ROLE_NAME = "iam-identity-center-cross-account-discovery-role"
    EXTERNAL_ID = "iam-identity-center-discovery"

    sts_client = get_aws_client('sts')

    logger.info(f"Will scan {len(sso_regions)} regions per account for account-level instances")

    for account in accounts:
        account_id = account.get('Id')
        account_name = account.get('Name', 'Unknown')
        account_status = account.get('Status', 'UNKNOWN')

        if not account_id:
            logger.warning(f"Account missing ID, skipping: {account}")
            continue

        if account_status != 'ACTIVE':
            logger.info(f"Skipping non-active account {account_id} ({account_name}): status={account_status}")
            continue

        # Note: We DO scan the current account for account-level instances
        # Organization-level discovery only finds org-level instances, not account-level ones

        stats['accounts_scanned'] += 1
        logger.info(f"Scanning account {account_id} ({account_name}) across {len(sso_regions)} regions")

        try:
            # Acquire credentials once per account, then reuse across all regions
            credentials = None
            role_arn = None

            if account_id == current_account:
                logger.info(f"  Using current credentials for account {account_id}")
                stats['accounts_with_role_access'] += 1
            else:
                # Try to assume cross-account role
                role_arn = f"arn:aws:iam::{account_id}:role/{CROSS_ACCOUNT_ROLE_NAME}"

                try:
                    logger.info(f"  Attempting to assume role: {role_arn}")
                    assume_response = sts_client.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=f"IAMIdentityCenterDiscovery-{account_id}",
                        ExternalId=EXTERNAL_ID,
                        DurationSeconds=900
                    )

                    credentials = assume_response['Credentials']
                    stats['accounts_with_role_access'] += 1
                    logger.info(f"  ✅ Successfully assumed role in account {account_id}")

                except ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code in ['AccessDenied', 'AccessDeniedException']:
                        stats['accounts_without_role'] += 1
                        logger.warning(f"  ⚠️  Cannot assume role in account {account_id}: {error_code}")
                        logger.warning(f"  Cross-account role '{CROSS_ACCOUNT_ROLE_NAME}' may not be deployed")
                        continue
                    else:
                        raise

            # Scan all regions for this account
            account_instance_count = 0

            for region in sso_regions:
                try:
                    sso_client = create_sso_client_for_region(region, credentials)

                    # List instances in this region with pagination
                    def _list_all_instances(client=sso_client):
                        all_instances = []
                        next_token = None
                        while True:
                            params = {}
                            if next_token:
                                params['NextToken'] = next_token
                            response = client.list_instances(**params)
                            all_instances.extend(response.get('Instances', []))
                            next_token = response.get('NextToken')
                            if not next_token:
                                break
                        return {'Instances': all_instances}

                    success, api_result, error = safe_api_call(
                        _list_all_instances,
                        f"Listing instances in account {account_id} region {region}",
                        continue_on_error=True
                    )

                    if not success:
                        # Log access denied at debug level per-region to avoid noise
                        if 'AccessDeniedException' in str(error) or 'is not authorized to perform' in str(error):
                            logger.debug(f"  SSO not accessible in {region} for account {account_id}")
                        else:
                            logger.warning(f"  Region {region} skipped for account {account_id}, instances not listed: {error}")
                        continue

                    stats['regions_scanned'] += 1
                    instances_in_region = api_result.get('Instances', [])

                    # Filter to instances owned by this account (excludes org-level instances)
                    account_owned_instances = [
                        inst for inst in instances_in_region
                        if inst.get('OwnerAccountId') == account_id
                    ]

                    if not account_owned_instances:
                        continue

                    stats['regions_with_instances'] += 1
                    logger.info(f"  Found {len(account_owned_instances)} instance(s) in {region}")

                    # Process each instance found in this region
                    for instance_data in account_owned_instances:
                        try:
                            instance_arn = instance_data.get('InstanceArn')

                            # Deduplicate: same instance ARN should not appear twice
                            if instance_arn in seen_instance_arns:
                                logger.debug(f"  Skipping duplicate instance: {instance_arn}")
                                continue
                            seen_instance_arns.add(instance_arn)

                            identity_store_id = instance_data.get('IdentityStoreId')
                            status = instance_data.get('Status', 'ACTIVE')
                            created_date = instance_data.get('CreatedDate')

                            logger.info(f"  Processing instance: {instance_arn} (region: {region})")

                            instance = create_instance_object(
                                instance_arn=instance_arn,
                                owner_account_id=account_id,
                                region=region,
                                instance_type=InstanceType.ACCOUNT.value,
                                status=status,
                                identity_store_id=identity_store_id,
                                created_date=created_date,
                                discovery_run_id=discovery_run_id,
                                discovered_by="instance-scanner",
                                discovery_method="cross_account_multi_region_scan",
                                account_name=account_name,
                                role_arn=role_arn
                            )

                            instances.append(instance)
                            account_instance_count += 1
                            logger.info(f"  ✅ Successfully processed instance: {instance_arn}")

                        except Exception as e:
                            logger.error(f"  Error processing instance {instance_data.get('InstanceArn')}: {str(e)}")
                            continue

                except Exception as e:
                    # Region-level errors should not stop scanning other regions
                    logger.warning(f"  Region {region} skipped for account {account_id}: {str(e)}")
                    continue

            if account_instance_count > 0:
                logger.info(f"  Account {account_id} total: {account_instance_count} account-level instance(s)")
            else:
                logger.info(f"  No account-level instances found in {account_id}")

        except Exception as e:
            logger.error(f"Error scanning account {account_id} ({account_name}): {str(e)}")
            continue

    logger.info(f"Multi-region scan complete: {stats['regions_scanned']} region scans across {stats['accounts_scanned']} accounts")
    return instances, stats

def create_instance_object(
    instance_arn: str,
    owner_account_id: str,
    region: str,
    instance_type: str,
    status: str,
    identity_store_id: str,
    created_date: Any,
    discovery_run_id: str,
    discovered_by: str,
    discovery_method: str,
    account_name: str = None,
    role_arn: str = None
) -> Instance:
    """
    Create an Instance object with proper formatting and validation.
    
    Args:
        instance_arn: Instance ARN
        owner_account_id: Account ID that owns the instance
        region: AWS region
        instance_type: Type of instance (organization or account)
        status: Instance status
        identity_store_id: Identity Store ID
        created_date: Creation date
        discovery_run_id: Discovery run ID
        discovered_by: Component that discovered the instance
        discovery_method: Method used for discovery
        account_name: Optional account name
        role_arn: Optional cross-account role ARN
    
    Returns:
        Instance object
    """
    # Format created_date properly
    formatted_created_date = None
    if created_date:
        if isinstance(created_date, str):
            if '+00:00Z' in created_date:
                formatted_created_date = created_date.replace('+00:00Z', '+00:00')
            else:
                formatted_created_date = created_date
        else:
            formatted_created_date = created_date.isoformat() + 'Z'
    
    # Create discovery metadata
    discovery_metadata = {
        'discovered_by': discovered_by,
        'discovery_run_id': discovery_run_id,
        'source_account': owner_account_id,
        'discovery_method': discovery_method
    }
    
    if account_name:
        discovery_metadata['account_name'] = account_name
    
    if role_arn:
        discovery_metadata['role_arn'] = role_arn
    
    # Create Instance object with validation
    return Instance(
        instance_arn=instance_arn,
        account_id=owner_account_id,
        region=region,
        instance_type=instance_type,
        status=status,
        identity_store_id=identity_store_id,
        created_date=formatted_created_date,
        last_updated=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        discovery_metadata=discovery_metadata
    )

@trace_aws_api_call("organizations", "describe_organization")
def get_organization_info(org_client: boto3.client) -> Dict[str, Any]:
    """Get organization information with retry logic."""
    def _describe_org():
        return org_client.describe_organization()
    
    success, result, error = safe_api_call(
        _describe_org, 
        "Getting organization information",
        continue_on_error=True
    )
    
    if success:
        return result.get('Organization', {})
    elif error and 'AWSOrganizationsNotInUseException' in error:
        logger.warning("AWS Organizations is not enabled for this account")
        return {}
    else:
        logger.error(f"Failed to get organization info: {error}")
        return {}

@trace_aws_api_call("organizations", "list_accounts")
def get_organization_accounts(org_client: boto3.client) -> List[Dict[str, Any]]:
    """Get all accounts in the organization with retry logic."""
    def _list_accounts():
        return paginate_api_call(org_client, 'list_accounts')
    
    success, result, error = safe_api_call(
        _list_accounts,
        "Listing organization accounts",
        continue_on_error=True
    )
    
    if success:
        logger.info(f"Retrieved {len(result)} accounts from organization")
        return result
    else:
        logger.error(f"Failed to list organization accounts: {error}")
        return []

def extract_region_from_arn(arn: str) -> str:
    """Extract AWS region from ARN."""
    if not arn:
        return None
    
    try:
        parts = arn.split(':')
        if len(parts) >= 4:
            return parts[3] if parts[3] else None
    except Exception:
        pass
    
    return None

def convert_to_dynamodb_item(data: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a Python dictionary to DynamoDB item format."""
    def convert_value(value):
        if value is None:
            return {'NULL': True}
        elif isinstance(value, bool):
            return {'BOOL': value}
        elif isinstance(value, (int, float)):
            return {'N': str(value)}
        elif isinstance(value, str):
            return {'S': value}
        elif isinstance(value, dict):
            return {'M': {k: convert_value(v) for k, v in value.items()}}
        elif isinstance(value, list):
            return {'L': [convert_value(item) for item in value]}
        else:
            return {'S': str(value)}
    
    return {key: convert_value(value) for key, value in data.items() if value is not None}

@trace_aws_api_call("dynamodb", "batch_write_item")
def persist_instances_to_dynamodb(instances: List[Instance], discovery_run_id: str) -> bool:
    """Persist discovered instances to DynamoDB."""
    if not instances:
        logger.info("No instances to persist")
        return True
    
    try:
        import os
        table_name = os.environ.get('INSTANCES_TABLE', 'iam-identity-center-instances')
        
        dynamodb = get_aws_client('dynamodb')
        
        logger.info(f"Persisting {len(instances)} instances to DynamoDB table: {table_name}")

        # Deduplicate by instance_arn (DynamoDB primary key) before batch write.
        # Keep the first occurrence, which is the org-level entry when both org
        # and account scans return the same ARN.
        seen_arns = set()
        unique_instances = []
        for instance in instances:
            if instance.instance_arn not in seen_arns:
                seen_arns.add(instance.instance_arn)
                unique_instances.append(instance)
            else:
                logger.info(f"Deduplicating instance {instance.instance_arn} (keeping first occurrence)")

        if len(unique_instances) < len(instances):
            logger.info(f"Deduplicated {len(instances)} instances to {len(unique_instances)} unique entries")

        # Prepare batch write items
        write_requests = []
        for instance in unique_instances:
            instance_dict = instance.to_dict()
            dynamodb_item = convert_to_dynamodb_item(instance_dict)

            write_requests.append({
                'PutRequest': {
                    'Item': dynamodb_item
                }
            })
        
        # Batch write in chunks of 25 (DynamoDB limit)
        batch_size = 25
        for i in range(0, len(write_requests), batch_size):
            batch = write_requests[i:i + batch_size]
            
            response = dynamodb.batch_write_item(
                RequestItems={
                    table_name: batch
                }
            )
            
            # Handle unprocessed items
            unprocessed = response.get('UnprocessedItems', {})
            retry_count = 0
            max_retries = 3
            
            while unprocessed and retry_count < max_retries:
                logger.warning(f"Retrying {len(unprocessed.get(table_name, []))} unprocessed items")
                import time
                time.sleep(2 ** retry_count)
                
                response = dynamodb.batch_write_item(RequestItems=unprocessed)
                unprocessed = response.get('UnprocessedItems', {})
                retry_count += 1
            
            if unprocessed:
                logger.error(f"Failed to write {len(unprocessed.get(table_name, []))} items after {max_retries} retries")
        
        logger.info(f"Successfully persisted {len(unique_instances)} instances to DynamoDB")
        return True
        
    except Exception as e:
        logger.error(f"Failed to persist instances to DynamoDB: {str(e)}")
        return False
