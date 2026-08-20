# Access Tracker Lambda Function
# Enriches assignment data with last-accessed timestamps from CloudTrail
#
# PERSONAL DATA: this function reads UserName from the Identity Store (typically
# an email address or login identifier) and writes per-person last-accessed
# history to DynamoDB. That combination -- who holds access to what, and when
# they last used it -- is personal data under the GDPR and comparable regimes,
# and it is a behavioural record, not just an identifier.
#
# Under the AWS shared responsibility model the deploying account owns lawful
# basis, retention, data residency, access control, and erasure for it. Note that
# DynamoDB point-in-time recovery is enabled by default here, which extends the
# window in which this data remains recoverable after deletion. See "Data
# protection and your compliance obligations" in the repository README.

import json
import boto3
import logging
import os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone, timedelta

# Add parent directory to path for shared imports
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.utils import setup_logging, handle_api_error, safe_api_call, redact_principal, get_cross_account_external_id, redact_assignment_id
from shared.tracing import init_xray_tracing, trace_lambda_handler

# Initialize X-Ray tracing
init_xray_tracing("access-tracker")

logger = setup_logging(__name__)

# Default configuration
DEFAULT_LOOKBACK_DAYS = 90  # CloudTrail LookupEvents limit without a trail
DEFAULT_STALE_THRESHOLD_DAYS = 30  # Default threshold for stale assignment flag


@trace_lambda_handler
def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for enriching assignments with last-accessed data from CloudTrail.
    
    Expected event format:
    {
        "action": "enrich_last_accessed",
        "discovery_run_id": "uuid",
        "lookback_days": 90,           # Optional, default 90
        "stale_threshold_days": 30     # Optional, default 30
    }
    
    Returns:
    {
        "statusCode": 200,
        "body": {
            "success": true,
            "message": "...",
            "assignments_updated": 150,
            "assignments_marked_stale": 25,
            "errors": []
        }
    }
    """
    logger.info("Starting access tracker enrichment")
    
    try:
        # Extract parameters
        action = event.get('action', 'enrich_last_accessed')
        discovery_run_id = event.get('discovery_run_id', 'manual')
        lookback_days = event.get('lookback_days', DEFAULT_LOOKBACK_DAYS)
        stale_threshold_days = event.get('stale_threshold_days', DEFAULT_STALE_THRESHOLD_DAYS)
        
        # Validate lookback_days (CloudTrail limit)
        if lookback_days > 90:
            logger.warning(f"lookback_days {lookback_days} exceeds CloudTrail limit of 90, using 90")
            lookback_days = 90
        
        logger.info(f"Configuration: lookback_days={lookback_days}, stale_threshold_days={stale_threshold_days}")
        
        if action == 'enrich_last_accessed':
            result = enrich_assignments_with_last_accessed(
                discovery_run_id=discovery_run_id,
                lookback_days=lookback_days,
                stale_threshold_days=stale_threshold_days
            )
        else:
            raise ValueError(f"Unknown action: {action}")
        
        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }
        
    except Exception as e:
        logger.error(f"Access tracker failed: {str(e)}")
        return handle_api_error(e)


def get_instance_identity_store_mapping() -> Dict[str, Dict[str, str]]:
    """
    Get mapping of instance ARN to Identity Store ID and account ID from DynamoDB.
    
    Returns:
        Dictionary: {instance_arn: {'identity_store_id': str, 'account_id': str}}
    """
    table_name = os.environ.get('INSTANCES_TABLE')
    if not table_name:
        raise ValueError("INSTANCES_TABLE environment variable is required")
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)

    mapping = {}

    try:
        last_key = None
        while True:
            params = {
                'ProjectionExpression': 'instance_arn, identity_store_id, account_id, #r',
                'ExpressionAttributeNames': {'#r': 'region'}
            }
            if last_key:
                params['ExclusiveStartKey'] = last_key

            response = table.scan(**params)

            for item in response.get('Items', []):
                instance_arn = item.get('instance_arn')
                if instance_arn:
                    mapping[instance_arn] = {
                        'identity_store_id': item.get('identity_store_id'),
                        'account_id': item.get('account_id'),
                        'region': item.get('region')
                    }

            last_key = response.get('LastEvaluatedKey')
            if not last_key:
                break

        logger.info(f"Loaded {len(mapping)} instance mappings from DynamoDB")

    except Exception as e:
        logger.error(f"Error loading instance mappings: {e}")

    return mapping


def get_application_instance_mapping() -> Dict[str, str]:
    """
    Get mapping of application ARN to instance ARN from DynamoDB.
    
    Returns:
        Dictionary: {application_arn: instance_arn}
    """
    table_name = os.environ.get('APPLICATIONS_TABLE')
    if not table_name:
        raise ValueError("APPLICATIONS_TABLE environment variable is required")
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)
    
    mapping = {}
    
    try:
        last_key = None
        while True:
            params = {'ProjectionExpression': 'application_arn, instance_arn'}
            if last_key:
                params['ExclusiveStartKey'] = last_key
            
            response = table.scan(**params)
            
            for item in response.get('Items', []):
                app_arn = item.get('application_arn')
                inst_arn = item.get('instance_arn')
                if app_arn and inst_arn:
                    mapping[app_arn] = inst_arn
            
            last_key = response.get('LastEvaluatedKey')
            if not last_key:
                break
        
        logger.info(f"Loaded {len(mapping)} application-to-instance mappings")
        
    except Exception as e:
        logger.error(f"Error loading application mappings: {e}")
    
    return mapping


def get_delegated_admin_identity_store_id() -> Optional[str]:
    """
    Get the Identity Store ID from the SSO instance accessible via delegated admin.
    
    The delegated admin account has access to the management account's SSO instance.
    
    Returns:
        Identity Store ID or None if not found
    """
    try:
        sso_admin = boto3.client('sso-admin')
        response = sso_admin.list_instances()
        instances = response.get('Instances', [])
        
        if not instances:
            logger.warning("No SSO instances found")
            return None
        
        # The delegated admin sees the organization's SSO instance
        instance = instances[0]
        identity_store_id = instance.get('IdentityStoreId')
        
        logger.info(f"Delegated admin Identity Store: {identity_store_id}")
        return identity_store_id
        
    except Exception as e:
        logger.error(f"Error getting delegated admin Identity Store ID: {e}")
        return None


def get_cross_account_identitystore_client(account_id: str, region: Optional[str] = None) -> Optional[Any]:
    """
    Get an Identity Store client for a cross-account by assuming the discovery role.

    Args:
        account_id: The target AWS account ID
        region: Region of the target Identity Store instance. Identity Store is
            regional — a client in the wrong region raises
            ResourceNotFoundException ("IdentityStore not present").

    Returns:
        boto3 identitystore client or None if role assumption fails
    """
    try:
        sts = boto3.client('sts')
        role_arn = f"arn:aws:iam::{account_id}:role/iam-identity-center-cross-account-discovery-role"

        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='access-tracker-cross-account',
            ExternalId=get_cross_account_external_id()
        )

        credentials = response['Credentials']

        client = boto3.client(
            'identitystore',
            region_name=region,
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )
        
        logger.info(f"Assumed role in account {account_id} for Identity Store access")
        return client
        
    except Exception as e:
        logger.warning(f"Failed to assume role in account {account_id}: {e}")
        return None


def get_group_memberships_for_identity_store(
    identity_store_id: str,
    identitystore_client: Any
) -> Dict[str, List[str]]:
    """
    Get all group memberships from a specific Identity Store.
    
    Args:
        identity_store_id: The Identity Store ID
        identitystore_client: boto3 identitystore client (may be cross-account)
    
    Returns:
        Dictionary mapping group_id -> list of user_ids in that group
    """
    group_members: Dict[str, List[str]] = {}
    
    try:
        # First, list all groups
        groups = []
        next_token = None
        
        while True:
            params = {'IdentityStoreId': identity_store_id}
            if next_token:
                params['NextToken'] = next_token
            
            response = identitystore_client.list_groups(**params)
            groups.extend(response.get('Groups', []))
            
            next_token = response.get('NextToken')
            if not next_token:
                break
        
        logger.info(f"Found {len(groups)} groups in Identity Store {identity_store_id}")
        
        # For each group, get its members
        for group in groups:
            group_id = group.get('GroupId')
            if not group_id:
                continue
            
            members = []
            next_token = None
            
            while True:
                params = {
                    'IdentityStoreId': identity_store_id,
                    'GroupId': group_id
                }
                if next_token:
                    params['NextToken'] = next_token
                
                try:
                    response = identitystore_client.list_group_memberships(**params)
                    for membership in response.get('GroupMemberships', []):
                        member_id = membership.get('MemberId', {})
                        user_id = member_id.get('UserId')
                        if user_id:
                            members.append(user_id)
                    
                    next_token = response.get('NextToken')
                    if not next_token:
                        break
                except Exception as e:
                    logger.warning("Error getting memberships for group %s: %s", redact_principal(group_id), e)
                    break
            
            if members:
                group_members[group_id] = members
        
        total_memberships = sum(len(m) for m in group_members.values())
        logger.info(f"Loaded {total_memberships} group memberships across {len(group_members)} groups from {identity_store_id}")
        
    except Exception as e:
        logger.error(f"Error loading group memberships from {identity_store_id}: {e}")
    
    return group_members


def load_all_group_memberships(
    instance_mapping: Dict[str, Dict[str, str]],
    delegated_admin_identity_store_id: Optional[str],
    current_account_id: str
) -> Dict[str, Dict[str, List[str]]]:
    """
    Load group memberships for all Identity Stores, using cross-account roles when needed.
    
    Args:
        instance_mapping: {instance_arn: {'identity_store_id': str, 'account_id': str}}
        delegated_admin_identity_store_id: The Identity Store ID accessible directly
        current_account_id: The account ID where this Lambda is running
    
    Returns:
        Nested dict: {identity_store_id: {group_id: [user_ids]}}
    """
    all_memberships: Dict[str, Dict[str, List[str]]] = {}
    
    # Get unique identity stores with their account and region
    identity_stores_to_load: Dict[str, Dict[str, Optional[str]]] = {}

    for instance_arn, info in instance_mapping.items():
        identity_store_id = info.get('identity_store_id')
        account_id = info.get('account_id')
        if identity_store_id and account_id:
            identity_stores_to_load[identity_store_id] = {
                'account_id': account_id,
                'region': info.get('region')
            }

    logger.info(f"Need to load memberships from {len(identity_stores_to_load)} Identity Stores")

    for identity_store_id, store_info in identity_stores_to_load.items():
        account_id = store_info['account_id']
        region = store_info.get('region')
        # Determine if we can access directly or need cross-account
        if identity_store_id == delegated_admin_identity_store_id:
            # Delegated admin can access the org's Identity Store directly
            logger.info(f"Loading {identity_store_id} directly (delegated admin access)")
            client = boto3.client('identitystore')
            memberships = get_group_memberships_for_identity_store(identity_store_id, client)
            all_memberships[identity_store_id] = memberships
        elif account_id == current_account_id:
            # Same account, access directly (region may still differ)
            logger.info(f"Loading {identity_store_id} directly (same account)")
            client = boto3.client('identitystore', region_name=region)
            memberships = get_group_memberships_for_identity_store(identity_store_id, client)
            all_memberships[identity_store_id] = memberships
        else:
            # Cross-account, need to assume role
            logger.info(f"Loading {identity_store_id} via cross-account role in {account_id} ({region})")
            client = get_cross_account_identitystore_client(account_id, region)
            if client:
                memberships = get_group_memberships_for_identity_store(identity_store_id, client)
                all_memberships[identity_store_id] = memberships
            else:
                logger.warning(f"Skipping {identity_store_id} - could not assume cross-account role")
                all_memberships[identity_store_id] = {}
    
    total_groups = sum(len(m) for m in all_memberships.values())
    logger.info(f"Loaded memberships for {total_groups} groups across {len(all_memberships)} Identity Stores")
    
    return all_memberships


def get_user_name(
    user_id: str,
    identity_store_id: str,
    identitystore_client: Any,
    user_cache: Dict[str, str]
) -> Optional[str]:
    """
    Look up a user's username from Identity Store.
    
    Args:
        user_id: The user ID to look up
        identity_store_id: The Identity Store ID
        identitystore_client: boto3 identitystore client
        user_cache: Cache dict to store looked-up usernames
    
    Returns:
        User's username, or None if not found
    """
    # Check cache first
    cache_key = f"{identity_store_id}:{user_id}"
    if cache_key in user_cache:
        return user_cache[cache_key]
    
    try:
        response = identitystore_client.describe_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id
        )
        
        # Use UserName (typically the email or login identifier)
        username = response.get('UserName')
        
        user_cache[cache_key] = username
        return username
        
    except Exception as e:
        logger.warning("Error looking up user %s: %s", redact_principal(user_id), e)
        user_cache[cache_key] = None
        return None


def get_identitystore_client_for_store(
    identity_store_id: str,
    instance_mapping: Dict[str, Dict[str, str]],
    delegated_admin_identity_store_id: Optional[str],
    current_account_id: str
) -> Optional[Any]:
    """
    Get the appropriate Identity Store client for a given Identity Store ID.
    
    Args:
        identity_store_id: The Identity Store ID
        instance_mapping: {instance_arn: {'identity_store_id': str, 'account_id': str}}
        delegated_admin_identity_store_id: The Identity Store ID accessible directly
        current_account_id: The account ID where this Lambda is running
    
    Returns:
        boto3 identitystore client or None
    """
    # Find the account for this identity store
    account_id = None
    for instance_arn, info in instance_mapping.items():
        if info.get('identity_store_id') == identity_store_id:
            account_id = info.get('account_id')
            break
    
    if not account_id:
        return None
    
    if identity_store_id == delegated_admin_identity_store_id:
        return boto3.client('identitystore')
    elif account_id == current_account_id:
        return boto3.client('identitystore')
    else:
        return get_cross_account_identitystore_client(account_id)


def enrich_assignments_with_last_accessed(
    discovery_run_id: str,
    lookback_days: int,
    stale_threshold_days: int
) -> Dict[str, Any]:
    """
    Main enrichment logic: query CloudTrail and update assignments.
    
    For GROUP assignments, we check if any member of the group has accessed
    the application and use the most recent access time.
    
    The logic determines which Identity Store each application belongs to,
    and uses cross-account role assumption when needed to look up group memberships.
    
    Args:
        discovery_run_id: ID of the current discovery run
        lookback_days: How far back to query CloudTrail (max 90)
        stale_threshold_days: Days threshold for marking assignment as stale
    
    Returns:
        Result dictionary with counts and errors
    """
    result = {
        'success': True,
        'message': '',
        'discovery_run_id': discovery_run_id,
        'assignments_scanned': 0,
        'assignments_updated': 0,
        'assignments_marked_stale': 0,
        'assignments_never_accessed': 0,
        'assignments_access_unknown': 0,
        'assignments_with_access': 0,
        'group_assignments_processed': 0,
        'errors': [],
        'stale_threshold_days': stale_threshold_days
    }
    
    try:
        # Step 1: Load mappings from DynamoDB (needed for cross-account CloudTrail queries)
        logger.info("Loading instance and application mappings")
        instance_mapping = get_instance_identity_store_mapping()
        app_to_instance = get_application_instance_mapping()

        # Step 2: Get current account ID and delegated admin Identity Store
        sts = boto3.client('sts')
        current_account_id = sts.get_caller_identity()['Account']
        delegated_admin_identity_store_id = get_delegated_admin_identity_store_id()

        logger.info(f"Current account: {current_account_id}, Delegated admin Identity Store: {delegated_admin_identity_store_id}")

        # Step 3: Get all CreateTokenWithIAM events from CloudTrail (local + cross-account)
        logger.info(f"Querying CloudTrail for CreateTokenWithIAM events (last {lookback_days} days)")
        access_data, access_data_complete = get_authentication_events(lookback_days, instance_mapping, current_account_id)
        unique_principals = len(access_data)
        total_accesses = sum(len(apps) for apps in access_data.values())
        logger.info(f"Found {unique_principals} users with {total_accesses} application accesses")

        # Step 4: Load group memberships for all Identity Stores
        logger.info("Loading group memberships from all Identity Stores")
        all_group_memberships = load_all_group_memberships(
            instance_mapping,
            delegated_admin_identity_store_id,
            current_account_id
        )
        
        # Step 5: Scan all assignments from DynamoDB
        logger.info("Scanning assignments table")
        assignments = scan_all_assignments()
        result['assignments_scanned'] = len(assignments)
        logger.info(f"Found {len(assignments)} assignments to process")
        
        # Step 6: Enrich each assignment with last-accessed data
        now = datetime.now(timezone.utc)
        updates = []
        
        # Cache for user name lookups to avoid repeated API calls
        user_name_cache: Dict[str, str] = {}
        
        # Track which user IDs need name resolution and their identity stores
        users_to_resolve: Dict[str, str] = {}  # {user_id: identity_store_id}
        
        # First pass: collect all user IDs that need resolution
        preliminary_results = []
        
        for assignment in assignments:
            try:
                principal_id = assignment.get('principal_id')
                principal_type = assignment.get('principal_type', '').upper()
                assignment_id = assignment.get('assignment_id')
                application_arn = assignment.get('application_arn')
                
                if not principal_id or not assignment_id:
                    continue
                
                last_accessed = None
                last_accessed_user_id = None
                identity_store_id = None
                
                if principal_type == 'GROUP':
                    # For GROUP assignments, determine which Identity Store this app belongs to
                    result['group_assignments_processed'] += 1
                    
                    # Find the Identity Store for this application
                    instance_arn = app_to_instance.get(application_arn)
                    if instance_arn:
                        instance_info = instance_mapping.get(instance_arn, {})
                        identity_store_id = instance_info.get('identity_store_id')
                    
                    # Get group memberships for this Identity Store
                    if identity_store_id:
                        store_memberships = all_group_memberships.get(identity_store_id, {})
                        group_members = store_memberships.get(principal_id, [])
                        
                        for member_user_id in group_members:
                            user_access = access_data.get(member_user_id, {})
                            user_app_access = user_access.get(application_arn) if application_arn else None
                            
                            if user_app_access:
                                if last_accessed is None or user_app_access > last_accessed:
                                    last_accessed = user_app_access
                                    last_accessed_user_id = member_user_id
                    else:
                        logger.debug(f"Could not determine Identity Store for application {application_arn}")
                else:
                    # For USER assignments, check direct access
                    user_access = access_data.get(principal_id, {})
                    last_accessed = user_access.get(application_arn) if application_arn else None
                    if last_accessed:
                        last_accessed_user_id = principal_id
                        # Find identity store for this user
                        instance_arn = app_to_instance.get(application_arn)
                        if instance_arn:
                            instance_info = instance_mapping.get(instance_arn, {})
                            identity_store_id = instance_info.get('identity_store_id')
                
                # Track user for name resolution
                if last_accessed_user_id and identity_store_id:
                    users_to_resolve[last_accessed_user_id] = identity_store_id
                
                preliminary_results.append({
                    'assignment_id': assignment_id,
                    'last_accessed': last_accessed,
                    'last_accessed_user_id': last_accessed_user_id,
                    'identity_store_id': identity_store_id
                })
                    
            except Exception as e:
                error_msg = f"Error processing assignment {redact_assignment_id(assignment.get('assignment_id'))}: {str(e)}"
                logger.warning(error_msg)
                result['errors'].append(error_msg)
        
        # Step 7: Resolve user names in batch
        logger.info(f"Resolving names for {len(users_to_resolve)} users")
        
        for user_id, identity_store_id in users_to_resolve.items():
            client = get_identitystore_client_for_store(
                identity_store_id,
                instance_mapping,
                delegated_admin_identity_store_id,
                current_account_id
            )
            if client:
                get_user_name(user_id, identity_store_id, client, user_name_cache)
        
        # Step 8: Build final updates with resolved user names
        for prelim in preliminary_results:
            assignment_id = prelim['assignment_id']
            last_accessed = prelim['last_accessed']
            last_accessed_user_id = prelim['last_accessed_user_id']
            identity_store_id = prelim['identity_store_id']
            
            # Calculate days since last access
            if last_accessed:
                if isinstance(last_accessed, str):
                    last_accessed_dt = datetime.fromisoformat(last_accessed.replace('Z', '+00:00'))
                else:
                    last_accessed_dt = last_accessed

                days_since = (now - last_accessed_dt).days
                accessed_in_threshold = days_since <= stale_threshold_days
                last_accessed_iso = last_accessed_dt.isoformat().replace('+00:00', 'Z')
                result['assignments_with_access'] += 1

                # Resolve user name
                last_accessed_principal_user = None
                if last_accessed_user_id and identity_store_id:
                    cache_key = f"{identity_store_id}:{last_accessed_user_id}"
                    last_accessed_principal_user = user_name_cache.get(cache_key)
            else:
                # No access found for this assignment
                days_since = None
                accessed_in_threshold = False
                last_accessed_iso = None
                last_accessed_principal_user = None
                # Only a complete CloudTrail read can confirm "never accessed".
                if access_data_complete:
                    result['assignments_never_accessed'] += 1
                else:
                    result['assignments_access_unknown'] = result.get('assignments_access_unknown', 0) + 1

            # Prepare update
            # Only claim the source when access history was actually obtained.
            # When CloudTrail could not be fully queried, "no access found" means
            # "unknown", not "never accessed" -- conflating them marks live
            # assignments as stale.
            if last_accessed_iso:
                access_status = 'ACCESSED'
            elif access_data_complete:
                access_status = 'NEVER_ACCESSED'
            else:
                access_status = 'UNKNOWN'

            update_data = {
                'assignment_id': assignment_id,
                'last_accessed': last_accessed_iso,
                'last_accessed_status': access_status,
                'last_accessed_source': (
                    'cloudtrail_CreateTokenWithIAM' if access_status != 'UNKNOWN' else None
                ),
                'last_accessed_principal_user': last_accessed_principal_user,
                'days_since_last_access': days_since,
                'accessed_in_last_x_days': accessed_in_threshold,
                'access_threshold_days': stale_threshold_days,
                'access_tracking_updated': now.isoformat().replace('+00:00', 'Z')
            }
            updates.append(update_data)

            # Never mark stale on an unknown: that is the input to access-revocation
            # decisions, and "we could not check" is not evidence of disuse.
            if not accessed_in_threshold and access_status != 'UNKNOWN':
                result['assignments_marked_stale'] += 1
        
        # Step 9: Batch update assignments in DynamoDB
        logger.info(f"Updating {len(updates)} assignments in DynamoDB")
        update_result = batch_update_assignments(updates)
        result['assignments_updated'] = update_result['updated_count']
        result['errors'].extend(update_result.get('errors', []))
        
        # Set success based on errors
        if result['errors']:
            result['success'] = len(result['errors']) < len(assignments) * 0.1  # Allow 10% error rate
        
        result['message'] = (
            f"Processed {result['assignments_scanned']} assignments "
            f"({result['group_assignments_processed']} group assignments). "
            f"Updated {result['assignments_updated']}. "
            f"{result['assignments_with_access']} with recent access. "
            f"Marked {result['assignments_marked_stale']} as not accessed in last {stale_threshold_days} days. "
            f"{result['assignments_never_accessed']} never accessed."
        )
        logger.info(result['message'])
        
    except Exception as e:
        error_msg = f"Enrichment failed: {str(e)}"
        logger.error(error_msg)
        result['success'] = False
        result['errors'].append(error_msg)
        result['message'] = error_msg
    
    return result


def get_cross_account_cloudtrail_client(account_id: str) -> Optional[Any]:
    """
    Get a CloudTrail client for a cross-account by assuming the discovery role.

    Args:
        account_id: The target AWS account ID

    Returns:
        boto3 cloudtrail client or None if role assumption fails
    """
    try:
        sts = boto3.client('sts')
        role_arn = f"arn:aws:iam::{account_id}:role/iam-identity-center-cross-account-discovery-role"

        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName='access-tracker-cloudtrail',
            ExternalId=get_cross_account_external_id()
        )

        credentials = response['Credentials']

        client = boto3.client(
            'cloudtrail',
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken']
        )

        logger.info(f"Assumed role in account {account_id} for CloudTrail access")
        return client

    except Exception as e:
        logger.warning(f"Failed to assume role in account {account_id} for CloudTrail: {e}")
        return None


def _query_cloudtrail_events(
    cloudtrail_client: Any,
    start_time: datetime,
    end_time: datetime,
    access_data: Dict[str, Dict[str, datetime]],
    account_label: str
) -> int:
    """
    Query a single CloudTrail client for CreateTokenWithIAM events and merge into access_data.

    Args:
        cloudtrail_client: boto3 cloudtrail client (local or cross-account)
        start_time: Start of lookup window
        end_time: End of lookup window
        access_data: Shared dict to merge results into {principal_id: {app_arn: datetime}}
        account_label: Label for logging (e.g. account ID)

    Returns:
        Number of events processed from this client
    """
    next_token = None
    total_events = 0

    while True:
        try:
            params = {
                'LookupAttributes': [
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'CreateTokenWithIAM'
                    }
                ],
                'StartTime': start_time,
                'EndTime': end_time,
                'MaxResults': 50
            }

            if next_token:
                params['NextToken'] = next_token

            response = cloudtrail_client.lookup_events(**params)
            events = response.get('Events', [])
            total_events += len(events)

            for event in events:
                try:
                    event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                    event_time = event.get('EventTime')

                    if event_data.get('eventSource', '') != 'sso-oauth.amazonaws.com':
                        continue

                    request_params = event_data.get('requestParameters', {})
                    application_arn = request_params.get('clientId')

                    additional_data = event_data.get('additionalEventData', {})
                    principal_id = additional_data.get('identitystore:UserId')

                    if principal_id and application_arn and event_time:
                        if principal_id not in access_data:
                            access_data[principal_id] = {}

                        current = access_data[principal_id].get(application_arn)
                        if current is None or event_time > current:
                            access_data[principal_id][application_arn] = event_time

                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    logger.warning(f"Error processing CloudTrail event in {account_label}: {e}")
                    continue

            next_token = response.get('NextToken')
            if not next_token:
                break

        except Exception as e:
            # The query aborted partway. Returning only the events gathered so far
            # would be indistinguishable from "this principal never signed in",
            # which downstream marks as stale. Report incompleteness instead.
            logger.error(f"Error querying CloudTrail in {account_label}: {e}")
            return total_events, False

    logger.info(f"Processed {total_events} CloudTrail events from {account_label}")
    return total_events, True


def get_authentication_events(
    lookback_days: int,
    instance_mapping: Optional[Dict[str, Dict[str, str]]] = None,
    current_account_id: Optional[str] = None
) -> Tuple[Dict[str, Dict[str, datetime]], bool]:
    """
    Query CloudTrail for CreateTokenWithIAM events from sso-oauth.amazonaws.com.

    Queries CloudTrail in the local account AND in every account that hosts an
    IdC instance (via cross-account role assumption), so that SSO authentication
    events logged in the management account or other member accounts are captured.

    Args:
        lookback_days: Number of days to look back (max 90)
        instance_mapping: {instance_arn: {'identity_store_id': str, 'account_id': str}}
        current_account_id: The account ID where this Lambda is running

    Returns:
        Nested dictionary: {principal_id: {application_arn: most_recent_timestamp}}
    """
    access_data: Dict[str, Dict[str, datetime]] = {}

    start_time = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end_time = datetime.now(timezone.utc)

    logger.info(f"Querying CloudTrail from {start_time.isoformat()} to {end_time.isoformat()}")

    # 1. Query the local account's CloudTrail
    local_client = boto3.client('cloudtrail')
    total_events, access_data_complete = _query_cloudtrail_events(
        local_client, start_time, end_time, access_data,
        f"local ({current_account_id or 'current'})"
    )

    # 2. Query CloudTrail in each cross-account that hosts an IdC instance
    if instance_mapping and current_account_id:
        remote_accounts = set()
        for info in instance_mapping.values():
            acct = info.get('account_id')
            if acct and acct != current_account_id:
                remote_accounts.add(acct)

        for account_id in sorted(remote_accounts):
            logger.info(f"Querying CloudTrail in cross-account {account_id}")
            ct_client = get_cross_account_cloudtrail_client(account_id)
            if ct_client:
                remote_events, remote_complete = _query_cloudtrail_events(
                    ct_client, start_time, end_time, access_data, account_id
                )
                total_events += remote_events
                access_data_complete = access_data_complete and remote_complete
            else:
                # An un-assumable role means this account's sign-in history was
                # never consulted, so the overall picture is incomplete.
                logger.warning(f"Skipping CloudTrail in {account_id} - could not assume role")
                access_data_complete = False

    unique_principals = len(access_data)
    total_accesses = sum(len(apps) for apps in access_data.values())
    logger.info(f"Processed {total_events} total CloudTrail events, found {unique_principals} principals with {total_accesses} application accesses")
    if not access_data_complete:
        logger.warning(
            "CloudTrail access history is INCOMPLETE -- assignments without a "
            "recorded access will be reported as UNKNOWN rather than never accessed"
        )
    return access_data, access_data_complete


def scan_all_assignments() -> List[Dict[str, Any]]:
    """
    Scan all assignments from DynamoDB.
    
    Returns:
        List of assignment dictionaries
    """
    table_name = os.environ.get('ASSIGNMENTS_TABLE')
    if not table_name:
        raise ValueError("ASSIGNMENTS_TABLE environment variable is required")
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)

    assignments = []
    last_evaluated_key = None
    
    while True:
        scan_params = {
            'ProjectionExpression': 'assignment_id, principal_id, principal_type, principal_name, application_arn'
        }
        
        if last_evaluated_key:
            scan_params['ExclusiveStartKey'] = last_evaluated_key
        
        response = table.scan(**scan_params)
        assignments.extend(response.get('Items', []))
        
        last_evaluated_key = response.get('LastEvaluatedKey')
        if not last_evaluated_key:
            break
    
    return assignments


def batch_update_assignments(updates: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Batch update assignments in DynamoDB with last-accessed data.
    
    Args:
        updates: List of update dictionaries containing assignment_id and new fields
    
    Returns:
        Result dictionary with updated count and errors
    """
    table_name = os.environ.get('ASSIGNMENTS_TABLE')
    if not table_name:
        raise ValueError("ASSIGNMENTS_TABLE environment variable is required")
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(table_name)

    result = {
        'updated_count': 0,
        'errors': []
    }

    for update in updates:
        try:
            assignment_id = update.get('assignment_id')
            if not assignment_id:
                continue

            # Build update expression dynamically, excluding the key field
            update_expression_parts = []
            expression_attribute_names = {}
            expression_attribute_values = {}

            for key, value in update.items():
                if key == 'assignment_id':
                    continue
                safe_key = f"#{key}"
                value_key = f":{key}"
                update_expression_parts.append(f"{safe_key} = {value_key}")
                expression_attribute_names[safe_key] = key
                expression_attribute_values[value_key] = value
            
            if not update_expression_parts:
                continue
            
            update_expression = "SET " + ", ".join(update_expression_parts)
            
            table.update_item(
                Key={'assignment_id': assignment_id},
                UpdateExpression=update_expression,
                ExpressionAttributeNames=expression_attribute_names,
                ExpressionAttributeValues=expression_attribute_values
            )
            
            result['updated_count'] += 1
            
        except Exception as e:
            error_msg = f"Failed to update assignment {redact_assignment_id(update.get('assignment_id'))}: {str(e)}"
            logger.warning(error_msg)
            result['errors'].append(error_msg)
    
    return result
