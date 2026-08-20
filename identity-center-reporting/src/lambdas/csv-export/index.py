"""
CSV Export Lambda Function for IAM Identity Center Discovery

This Lambda function handles CSV export requests for discovered IAM Identity Center data.
It supports exporting applications, assignments, and full datasets with filtering capabilities.

PERSONAL DATA: the exports produced here contain personal data about the people in the
Identity Store -- principal_name, principal_email, principal_display_name, principal IDs,
and per-person last-accessed history. The files are written to S3 and handed out through
presigned URLs, so an export leaves the boundary of the IAM controls that produced it.

Under the AWS shared responsibility model, the deploying account is responsible for
lawful basis, retention, data residency, access control, and deletion of that data --
which may engage the GDPR, UK GDPR, or CCPA/CPRA depending on the directory population.
See "Data protection and your compliance obligations" in the repository README before
widening who can call this function or where its output is sent.
"""

import json
import csv
import io
import os
import re
import boto3
from botocore.config import Config
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
import logging
import hashlib
from botocore.exceptions import ClientError
from shared.tracing import (
    init_xray_tracing, trace_lambda_handler, trace_discovery_operation,
    trace_aws_api_call, add_discovery_metrics, trace_performance_bottleneck
)

# Initialize X-Ray tracing
init_xray_tracing("csv-export")

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
dynamodb = boto3.resource('dynamodb')
s3_client = boto3.client('s3', config=Config(signature_version='s3v4'))

# Environment variables
INSTANCES_TABLE = os.environ.get('INSTANCES_TABLE', 'InstancesTable')
APPLICATIONS_TABLE = os.environ.get('APPLICATIONS_TABLE', 'ApplicationsTable')
ASSIGNMENTS_TABLE = os.environ.get('ASSIGNMENTS_TABLE', 'AssignmentsTable')
# No fallback bucket name: the bucket is CloudFormation-named, and a guessed
# default could resolve to a bucket owned by someone else (squatting risk).
S3_BUCKET = os.environ.get('CSV_EXPORT_BUCKET', '')
S3_PREFIX = 'exports'
PRESIGNED_URL_EXPIRY_SECONDS = 900  # 15 minutes; keep in sync with docs

def _caller_role(user_arn: str) -> str:
    """Return the role name from an assumed-role ARN, without the session name.

    The role identifies which access path was used, which is the part worth
    auditing. The session name is omitted because for IAM Identity Center it is
    the user's email address.
    """
    if not user_arn or user_arn == 'unknown':
        return 'unknown'
    parts = user_arn.split(':assumed-role/', 1)
    if len(parts) == 2:
        return parts[1].split('/', 1)[0]
    return user_arn.rsplit(':', 1)[-1].split('/', 1)[0] or 'unknown'


def _caller_digest(user_arn: str, length: int = 10) -> str:
    """Return a short, stable digest of the caller ARN for correlation.

    Same caller always yields the same digest, so requests can be grouped, but
    the value cannot be read back as an identity. Not a security control -- the
    input space is small enough to brute force if an attacker already knows the
    candidate ARNs -- it exists so routine log access does not expose who ran
    which export.
    """
    if not user_arn or user_arn == 'unknown':
        return 'unknown'
    return hashlib.sha256(user_arn.encode('utf-8')).hexdigest()[:length]


@trace_lambda_handler
def lambda_handler(event, context):
    """
    Main Lambda handler for CSV export requests

    Handles both API Gateway Lambda Proxy Integration events and direct invocations.

    API Gateway Proxy event (requestContext is camelCase, from AWS_PROXY integration):
    {
        "resource": "/export/applications",
        "path": "/export/applications",
        "httpMethod": "GET",
        "queryStringParameters": {"account_id": "123456789012", "region": "us-east-1"},
        "requestContext": {"requestId": "...", "identity": {"userArn": "..."}}
    }

    Direct invocation event:
    {
        "export_type": "applications|assignments|full",
        "filters": {"account_id": "123456789012", ...}
    }
    """
    is_api_gateway = False

    try:
        # Detect API Gateway Lambda Proxy Integration event
        # Proxy events have 'requestContext' (camelCase) and 'httpMethod'
        is_api_gateway = 'requestContext' in event and 'httpMethod' in event

        if is_api_gateway:
            # --- Parse API Gateway Proxy event ---
            # Extract export type from the resource path (e.g. "/export/applications")
            resource = event.get('resource', '')
            if resource.startswith('/export/'):
                export_type = resource.replace('/export/', '')
            else:
                export_type = 'full'

            # Extract filters from query string parameters
            query_params = event.get('queryStringParameters') or {}
            filters = {k: v for k, v in query_params.items() if v and v.strip()}

            # Extract request context
            api_context = event.get('requestContext', {})
            identity = api_context.get('identity', {})
            request_id = api_context.get('requestId', context.aws_request_id)
            user_arn = identity.get('userArn', 'unknown')
        else:
            # --- Parse direct invocation event ---
            export_type_raw = event.get('export_type', 'full')

            # Handle legacy API Gateway resource path format
            if export_type_raw.startswith('/export/'):
                export_type = export_type_raw.replace('/export/', '')
            else:
                export_type = export_type_raw

            # Parse filters and clean empty values
            filters = event.get('filters', {})
            filters = {k: v for k, v in filters.items() if v and v.strip()}

            # Log request details
            request_id = event.get('request_context', {}).get('request_id', context.aws_request_id)
            user_arn = event.get('request_context', {}).get('user_arn', 'unknown')
        
        # Log which filters were supplied, never their values, and identify the
        # caller by role plus a hash rather than by name.
        #
        # filters is caller-supplied and carries account IDs, application names and
        # principal types; user_arn names an individual principal. Both used to be
        # written verbatim to CloudWatch at INFO, putting request-level identity
        # data into logs retained far longer than the export itself.
        #
        # The trailing ARN segment is NOT a safe substitute: for a role assumed
        # through IAM Identity Center the session name is the user's email, so
        # arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_Admin_abc/user@example.com
        # reduces to user@example.com. Log the role name, which identifies the
        # access path being used, and a short digest of the full ARN, which lets
        # entries from one caller be correlated without naming them.
        logger.info(
            "Processing CSV export request: type=%s, filter_keys=%s, request_id=%s, "
            "caller_role=%s, caller_digest=%s",
            export_type, sorted(filters.keys()), request_id,
            _caller_role(user_arn), _caller_digest(user_arn)
        )
        
        # Validate export type
        if export_type not in ['applications', 'assignments', 'full']:
            error_response = {
                'error': 'Invalid export_type. Must be one of: applications, assignments, full',
                'provided_type': export_type
            }
            
            if is_api_gateway:
                return {
                    'statusCode': 400,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps(error_response)
                }
            else:
                return {
                    'statusCode': 400,
                    'body': json.dumps(error_response)
                }
        
        # Validate filters
        validation_error = validate_filters(filters)
        if validation_error:
            error_response = {
                'error': 'Invalid filter parameters',
                'details': validation_error
            }
            
            if is_api_gateway:
                return {
                    'statusCode': 400,
                    'headers': {
                        'Content-Type': 'application/json',
                        'Access-Control-Allow-Origin': '*'
                    },
                    'body': json.dumps(error_response)
                }
            else:
                return {
                    'statusCode': 400,
                    'body': json.dumps(error_response)
                }
        
        # Generate CSV data based on export type
        if export_type == 'applications':
            csv_data, filename = generate_applications_csv(filters)
        elif export_type == 'assignments':
            csv_data, filename = generate_assignments_csv(filters)
        else:  # full
            csv_data, filename = generate_full_csv(filters)
        
        # Upload to S3 and generate pre-signed URL
        s3_key = generate_s3_key(filename, export_type, filters)
        file_size = upload_to_s3(csv_data, s3_key)
        download_url = generate_presigned_url(s3_key)
        
        # Prepare success response
        success_response = {
            'message': 'CSV export generated successfully',
            'download_url': download_url,
            'filename': filename,
            's3_key': s3_key,
            'file_size_bytes': file_size,
            'export_type': export_type,
            'filters_applied': filters,
            'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'expires_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),  # Will be updated below
            'request_id': request_id
        }
        
        # Expiration must match the presigned URL's actual ExpiresIn (900s)
        expires_at = datetime.now(timezone.utc).timestamp() + PRESIGNED_URL_EXPIRY_SECONDS
        success_response['expires_at'] = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat().replace('+00:00', 'Z')
        
        if is_api_gateway:
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': 'https://*.amazonaws.com',
                    'Cache-Control': 'no-cache, no-store, must-revalidate'
                },
                'body': json.dumps(success_response)
            }
        else:
            return {
                'statusCode': 200,
                'body': json.dumps(success_response)
            }
        
    except Exception as e:
        logger.error(f"Error processing CSV export: {str(e)}")
        
        # Extract request_id from whichever event format was received
        if is_api_gateway:
            fallback_request_id = event.get('requestContext', {}).get('requestId', context.aws_request_id)
        else:
            fallback_request_id = event.get('request_context', {}).get('request_id', context.aws_request_id)

        error_response = {
            'error': 'Internal server error',
            'message': 'An unexpected error occurred. Check CloudWatch logs for details.',
            'request_id': fallback_request_id
        }

        if is_api_gateway:
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': 'https://*.amazonaws.com'
                },
                'body': json.dumps(error_response)
            }
        else:
            return {
                'statusCode': 500,
                'body': json.dumps(error_response)
            }

def validate_filters(filters: Dict[str, Any]) -> Optional[str]:
    """
    Validate filter parameters
    
    Args:
        filters: Dictionary of filter criteria
        
    Returns:
        Error message if validation fails, None if valid
    """
    if not filters:
        return None
    
    # Validate account ID format
    if 'account_id' in filters:
        account_id = filters['account_id']
        if not re.match(r'^\d{12}$', account_id):
            return f"Invalid account_id format: {account_id}. Must be 12 digits."
    
    # Validate region format
    if 'region' in filters:
        region = filters['region']
        if not re.match(r'^[a-z]{2}-[a-z]+-\d{1}$', region):
            return f"Invalid region format: {region}. Must be valid AWS region (e.g., us-east-1)."
    
    # Validate principal type
    if 'principal_type' in filters:
        principal_type = filters['principal_type']
        if principal_type not in ['USER', 'GROUP']:
            return f"Invalid principal_type: {principal_type}. Must be USER or GROUP."
    
    # Validate date formats
    for date_field in ['date_from', 'date_to']:
        if date_field in filters:
            date_value = filters[date_field]
            try:
                datetime.fromisoformat(date_value.replace('Z', '+00:00'))
            except ValueError:
                return f"Invalid {date_field} format: {date_value}. Must be ISO format (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)."
    
    # Validate date range
    if 'date_from' in filters and 'date_to' in filters:
        try:
            date_from = datetime.fromisoformat(filters['date_from'].replace('Z', '+00:00'))
            date_to = datetime.fromisoformat(filters['date_to'].replace('Z', '+00:00'))
            
            if date_from >= date_to:
                return "date_from must be earlier than date_to."
                
        except ValueError:
            pass  # Individual date validation will catch format errors
    
    # Validate application name length
    if 'application_name' in filters:
        app_name = filters['application_name']
        if len(app_name) > 255:
            return f"application_name too long: {len(app_name)} characters. Maximum 255 characters."
    
    return None

def sanitize_csv_row(row: list) -> list:
    """Strip NUL characters from string values. The csv module writes them,
    but csv readers (including Python's own) reject lines containing NUL."""
    return [v.replace('\x00', '') if isinstance(v, str) else v for v in row]

def generate_applications_csv(filters: Dict[str, Any]) -> tuple[str, str]:
    """
    Generate CSV export for applications data
    
    Args:
        filters: Dictionary of filter criteria
        
    Returns:
        Tuple of (csv_data, filename)
    """
    logger.info("Generating applications CSV export")
    
    # Query applications from DynamoDB
    applications = query_applications(filters)
    
    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    headers = [
        'Application ARN',
        'Instance ARN',
        'Application Name',
        'Description',
        'Status',
        'Provider ARN',
        'Account ID',
        'Region',
        'Portal Visibility',
        'Sign-in Origin',
        'Application URL',
        'Created Date',
        'Last Updated'
    ]
    writer.writerow(headers)
    
    # Write data rows
    for app in applications:
        portal_options = app.get('portal_options', {}) or {}
        sign_in_options = portal_options.get('SignInOptions', portal_options.get('sign_in_options', {})) or {}
        
        row = [
            app.get('application_arn', ''),
            app.get('instance_arn', ''),
            app.get('name', ''),
            app.get('description', ''),
            app.get('status', ''),
            app.get('application_provider_arn', ''),
            app.get('account_id', ''),
            app.get('region', ''),
            portal_options.get('Visibility', portal_options.get('visibility', '')),
            sign_in_options.get('Origin', sign_in_options.get('origin', '')),
            sign_in_options.get('ApplicationUrl', sign_in_options.get('application_url', '')),
            app.get('created_date', ''),
            app.get('last_updated', '')
        ]
        writer.writerow(sanitize_csv_row(row))
    
    csv_data = output.getvalue()
    output.close()
    
    # Generate filename with timestamp and filters
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    filter_suffix = generate_filter_suffix(filters)
    filename = f"applications_export_{timestamp}{filter_suffix}.csv"
    
    logger.info(f"Generated applications CSV with {len(applications)} records")
    return csv_data, filename

def generate_assignments_csv(filters: Dict[str, Any]) -> tuple[str, str]:
    """
    Generate CSV export for assignments data
    
    Args:
        filters: Dictionary of filter criteria
        
    Returns:
        Tuple of (csv_data, filename)
    """
    logger.info("Generating assignments CSV export")
    
    # Query assignments from DynamoDB
    assignments = query_assignments(filters)
    
    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Determine the access threshold from assignment data (default 30)
    access_threshold = 30
    for a in assignments:
        threshold_val = a.get('access_threshold_days')
        if threshold_val is not None and threshold_val != '':
            access_threshold = int(threshold_val)
            break

    # Write header with enhanced assignment metadata
    headers = [
        'Assignment ID',
        'Application ARN',
        'Application Name',
        'Principal ID',
        'Principal Type',
        'Principal Name',
        'Principal Display Name',
        'Principal Email',
        'Permission Set ARN',
        'Permission Set Name',
        'Account ID',
        'Instance ARN',
        'Assignment Status',
        'Matched',
        'Last Accessed',
        'Days Since Last Access',
        f'Accessed in the Last {access_threshold} Days',
        'Access Tracking Updated',
        'Last Updated'
    ]
    writer.writerow(headers)
    
    # Write data rows with enhanced metadata
    for assignment in assignments:
        # Extract matched value directly
        matched_value = assignment.get('matched', '')

        # Extract last-accessed tracking field
        accessed_in_last_x = assignment.get('accessed_in_last_x_days')
        accessed_str = 'Yes' if accessed_in_last_x is True else ('No' if accessed_in_last_x is False else '')

        row = [
            assignment.get('assignment_id', ''),
            assignment.get('application_arn', ''),
            assignment.get('application_name', ''),  # Will be populated by join query
            assignment.get('principal_id', ''),
            assignment.get('principal_type', ''),
            assignment.get('principal_name', ''),
            assignment.get('principal_display_name', ''),
            assignment.get('principal_email', ''),
            assignment.get('permission_set_arn', ''),
            assignment.get('permission_set_name', ''),
            assignment.get('account_id', ''),
            assignment.get('instance_arn', ''),
            assignment.get('assignment_status', ''),
            matched_value,
            assignment.get('last_accessed', ''),
            assignment.get('days_since_last_access', ''),
            accessed_str,
            assignment.get('access_tracking_updated', ''),
            assignment.get('last_updated', '')
        ]
        writer.writerow(sanitize_csv_row(row))
    
    csv_data = output.getvalue()
    output.close()
    
    # Generate filename with timestamp and filters
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    filter_suffix = generate_filter_suffix(filters)
    filename = f"assignments_export_{timestamp}{filter_suffix}.csv"
    
    logger.info(f"Generated assignments CSV with {len(assignments)} records")
    return csv_data, filename

def generate_full_csv(filters: Dict[str, Any]) -> tuple[str, str]:
    """
    Generate comprehensive CSV export with all data
    
    Args:
        filters: Dictionary of filter criteria
        
    Returns:
        Tuple of (csv_data, filename)
    """
    logger.info("Generating full CSV export")
    
    # Query all data types
    instances = query_instances(filters)
    applications = query_applications(filters)
    assignments = query_assignments(filters)
    
    # Create comprehensive dataset by joining data
    full_data = create_comprehensive_dataset(instances, applications, assignments)
    
    # Generate CSV
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Determine the access threshold from assignment data (default 30)
    access_threshold = 30
    for a in assignments:
        threshold_val = a.get('access_threshold_days')
        if threshold_val is not None and threshold_val != '':
            access_threshold = int(threshold_val)
            break

    # Write header
    headers = [
        'Instance ARN',
        'Instance Type',
        'Instance Status',
        'Identity Store ID',
        'Account ID',
        'Region',
        'Application ARN',
        'Application Name',
        'Application Description',
        'Application Status',
        'Application Provider ARN',
        'Portal Visibility',
        'Sign-in Origin',
        'Application URL',
        'Assignment ID',
        'Principal ID',
        'Principal Type',
        'Principal Name',
        'Principal Display Name',
        'Principal Email',
        'Permission Set ARN',
        'Permission Set Name',
        'Assignment Status',
        'Matched',
        'Last Accessed',
        'Last Accessed Principal User',
        'Days Since Last Access',
        f'Accessed in the Last {access_threshold} Days',
        'Access Tracking Updated',
        'Instance Last Updated',
        'Application Last Updated',
        'Assignment Last Updated'
    ]
    writer.writerow(headers)
    
    # Write data rows
    for record in full_data:
        # Extract accessed-in-last-X-days as string
        accessed_in_last_x = record.get('accessed_in_last_x_days')
        accessed_str = 'Yes' if accessed_in_last_x is True else ('No' if accessed_in_last_x is False else '')

        row = [
            record.get('instance_arn', ''),
            record.get('instance_type', ''),
            record.get('instance_status', ''),
            record.get('identity_store_id', ''),
            record.get('account_id', ''),
            record.get('region', ''),
            record.get('application_arn', ''),
            record.get('application_name', ''),
            record.get('application_description', ''),
            record.get('application_status', ''),
            record.get('application_provider_arn', ''),
            record.get('portal_visibility', ''),
            record.get('sign_in_origin', ''),
            record.get('application_url', ''),
            record.get('assignment_id', ''),
            record.get('principal_id', ''),
            record.get('principal_type', ''),
            record.get('principal_name', ''),
            record.get('principal_display_name', ''),
            record.get('principal_email', ''),
            record.get('permission_set_arn', ''),
            record.get('permission_set_name', ''),
            record.get('assignment_status', ''),
            record.get('matched', ''),
            record.get('last_accessed', ''),
            record.get('last_accessed_principal_user', ''),
            record.get('days_since_last_access', ''),
            accessed_str,
            record.get('access_tracking_updated', ''),
            record.get('instance_last_updated', ''),
            record.get('application_last_updated', ''),
            record.get('assignment_last_updated', '')
        ]
        writer.writerow(sanitize_csv_row(row))
    
    csv_data = output.getvalue()
    output.close()
    
    # Generate filename with timestamp and filters
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    filter_suffix = generate_filter_suffix(filters)
    filename = f"full_export_{timestamp}{filter_suffix}.csv"
    
    logger.info(f"Generated full CSV with {len(full_data)} records")
    return csv_data, filename

def query_instances(filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Query instances from DynamoDB with filtering
    
    Args:
        filters: Dictionary of filter criteria
        
    Returns:
        List of instance records
    """
    table = dynamodb.Table(INSTANCES_TABLE)
    
    try:
        # Build scan parameters with filters
        scan_params = {}
        filter_expressions = []
        expression_values = {}
        
        if filters.get('account_id'):
            filter_expressions.append('account_id = :account_id')
            expression_values[':account_id'] = filters['account_id']
        
        if filters.get('region'):
            filter_expressions.append('region = :region')
            expression_values[':region'] = filters['region']
        
        if filters.get('date_from'):
            filter_expressions.append('last_updated >= :date_from')
            expression_values[':date_from'] = filters['date_from']
        
        if filters.get('date_to'):
            filter_expressions.append('last_updated <= :date_to')
            expression_values[':date_to'] = filters['date_to']
        
        # A retired row is one discovery no longer finds and whose deletion has
        # already been reported. It is kept for the audit trail, so it must be
        # excluded here -- otherwise an export lists deleted applications and
        # revoked assignments as live access, which is the opposite of what a
        # least-privilege review needs.
        filter_expressions.append('attribute_not_exists(retired_at)')

        scan_params['FilterExpression'] = ' AND '.join(filter_expressions)
        if expression_values:
            scan_params['ExpressionAttributeValues'] = expression_values
        
        # Execute scan
        response = table.scan(**scan_params)
        items = response.get('Items', [])
        
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            scan_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = table.scan(**scan_params)
            items.extend(response.get('Items', []))
        
        logger.info(f"Retrieved {len(items)} instances")
        return items
        
    except ClientError as e:
        logger.error(f"Error querying instances: {e}")
        raise

def query_applications(filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Query applications from DynamoDB with filtering
    
    Args:
        filters: Dictionary of filter criteria
        
    Returns:
        List of application records
    """
    table = dynamodb.Table(APPLICATIONS_TABLE)
    
    try:
        # Build scan parameters with filters
        scan_params = {}
        filter_expressions = []
        expression_values = {}
        
        if filters.get('account_id'):
            filter_expressions.append('account_id = :account_id')
            expression_values[':account_id'] = filters['account_id']
        
        if filters.get('region'):
            filter_expressions.append('region = :region')
            expression_values[':region'] = filters['region']
        
        if filters.get('application_name'):
            filter_expressions.append('contains(#name, :app_name)')
            expression_values[':app_name'] = filters['application_name']
            scan_params['ExpressionAttributeNames'] = {'#name': 'name'}
        
        if filters.get('date_from'):
            filter_expressions.append('last_updated >= :date_from')
            expression_values[':date_from'] = filters['date_from']
        
        if filters.get('date_to'):
            filter_expressions.append('last_updated <= :date_to')
            expression_values[':date_to'] = filters['date_to']
        
        # A retired row is one discovery no longer finds and whose deletion has
        # already been reported. It is kept for the audit trail, so it must be
        # excluded here -- otherwise an export lists deleted applications and
        # revoked assignments as live access, which is the opposite of what a
        # least-privilege review needs.
        filter_expressions.append('attribute_not_exists(retired_at)')

        scan_params['FilterExpression'] = ' AND '.join(filter_expressions)
        if expression_values:
            scan_params['ExpressionAttributeValues'] = expression_values
        
        # Execute scan
        response = table.scan(**scan_params)
        items = response.get('Items', [])
        
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            scan_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = table.scan(**scan_params)
            items.extend(response.get('Items', []))
        
        logger.info(f"Retrieved {len(items)} applications")
        return items
        
    except ClientError as e:
        logger.error(f"Error querying applications: {e}")
        raise

def query_assignments(filters: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Query assignments from DynamoDB with filtering and application name enrichment
    
    Args:
        filters: Dictionary of filter criteria
        
    Returns:
        List of assignment records with application names
    """
    table = dynamodb.Table(ASSIGNMENTS_TABLE)
    
    try:
        # Build scan parameters with filters
        scan_params = {}
        filter_expressions = []
        expression_values = {}
        
        if filters.get('account_id'):
            filter_expressions.append('account_id = :account_id')
            expression_values[':account_id'] = filters['account_id']
        
        if filters.get('principal_type'):
            filter_expressions.append('principal_type = :principal_type')
            expression_values[':principal_type'] = filters['principal_type']
        
        if filters.get('date_from'):
            filter_expressions.append('last_updated >= :date_from')
            expression_values[':date_from'] = filters['date_from']
        
        if filters.get('date_to'):
            filter_expressions.append('last_updated <= :date_to')
            expression_values[':date_to'] = filters['date_to']
        
        # A retired row is one discovery no longer finds and whose deletion has
        # already been reported. It is kept for the audit trail, so it must be
        # excluded here -- otherwise an export lists deleted applications and
        # revoked assignments as live access, which is the opposite of what a
        # least-privilege review needs.
        filter_expressions.append('attribute_not_exists(retired_at)')

        scan_params['FilterExpression'] = ' AND '.join(filter_expressions)
        if expression_values:
            scan_params['ExpressionAttributeValues'] = expression_values
        
        # Execute scan
        response = table.scan(**scan_params)
        items = response.get('Items', [])
        
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            scan_params['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = table.scan(**scan_params)
            items.extend(response.get('Items', []))
        
        # Enrich with application names (and the application's region)
        items = enrich_assignments_with_app_names(items)

        # region and application_name are not attributes of assignment items —
        # both belong to the application — so they are applied here after
        # enrichment rather than in the DynamoDB FilterExpression. Silently
        # ignoring them would return unfiltered org-wide data.
        if filters.get('region'):
            items = [i for i in items if i.get('region') == filters['region']]

        if filters.get('application_name'):
            needle = filters['application_name'].lower()
            items = [i for i in items if needle in (i.get('application_name') or '').lower()]

        logger.info(f"Retrieved {len(items)} assignments")
        return items

    except ClientError as e:
        logger.error(f"Error querying assignments: {e}")
        raise

def enrich_assignments_with_app_names(assignments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich assignment records with application names and regions

    Args:
        assignments: List of assignment records

    Returns:
        List of enriched assignment records
    """
    if not assignments:
        return assignments

    # Get unique application ARNs
    app_arns = list(set(assignment.get('application_arn') for assignment in assignments if assignment.get('application_arn')))

    # Query application names using scan with filter
    # Note: applications table has composite key (application_arn PK + instance_arn SK),
    # so batch_get_item requires both keys. Use scan with projection instead.
    app_info = {}
    if app_arns:
        apps_table = dynamodb.Table(APPLICATIONS_TABLE)

        try:
            last_key = None
            while True:
                scan_params = {
                    'ProjectionExpression': 'application_arn, #name, #region',
                    'ExpressionAttributeNames': {'#name': 'name', '#region': 'region'}
                }
                if last_key:
                    scan_params['ExclusiveStartKey'] = last_key

                response = apps_table.scan(**scan_params)

                for item in response.get('Items', []):
                    app_arn = item.get('application_arn')
                    if app_arn in app_arns:
                        app_info[app_arn] = {
                            'name': item.get('name', ''),
                            'region': item.get('region', '')
                        }

                last_key = response.get('LastEvaluatedKey')
                if not last_key:
                    break

        except ClientError as e:
            logger.warning(f"Error scanning application names: {e}")

    # Enrich assignments with application names and regions
    for assignment in assignments:
        info = app_info.get(assignment.get('application_arn'), {})
        assignment['application_name'] = info.get('name', '')
        assignment.setdefault('region', info.get('region', ''))

    return assignments

def create_comprehensive_dataset(instances: List[Dict[str, Any]], 
                               applications: List[Dict[str, Any]], 
                               assignments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Create comprehensive dataset by joining instances, applications, and assignments
    
    Args:
        instances: List of instance records
        applications: List of application records
        assignments: List of assignment records
        
    Returns:
        List of comprehensive records
    """
    # Create lookup dictionaries
    instances_by_arn = {inst['instance_arn']: inst for inst in instances}
    applications_by_arn = {app['application_arn']: app for app in applications}
    
    comprehensive_data = []
    
    # Process assignments as the base (most detailed level)
    for assignment in assignments:
        app_arn = assignment.get('application_arn')
        instance_arn = assignment.get('instance_arn')
        
        # Get related application and instance data
        app_data = applications_by_arn.get(app_arn, {})
        instance_data = instances_by_arn.get(instance_arn, {})
        
        # Extract portal options (handle both lowercase and capitalized keys)
        portal_options = app_data.get('portal_options', {})
        sign_in_options = portal_options.get('SignInOptions', portal_options.get('sign_in_options', {}))
        
        # Extract matched value directly
        matched_value = assignment.get('matched', '')
        
        # Create comprehensive record
        record = {
            # Instance data
            'instance_arn': instance_data.get('instance_arn', instance_arn),
            'instance_type': instance_data.get('instance_type', ''),
            'instance_status': instance_data.get('status', ''),
            'identity_store_id': instance_data.get('identity_store_id', ''),
            'account_id': instance_data.get('account_id', assignment.get('account_id', '')),
            'region': instance_data.get('region', ''),
            
            # Application data
            'application_arn': app_data.get('application_arn', app_arn),
            'application_name': app_data.get('name', ''),
            'application_description': app_data.get('description', ''),
            'application_status': app_data.get('status', ''),
            'application_provider_arn': app_data.get('application_provider_arn', ''),
            'portal_visibility': portal_options.get('Visibility', portal_options.get('visibility', '')),
            'sign_in_origin': sign_in_options.get('Origin', sign_in_options.get('origin', '')),
            'application_url': sign_in_options.get('ApplicationUrl', sign_in_options.get('application_url', '')),
            
            # Assignment data
            'assignment_id': assignment.get('assignment_id', ''),
            'principal_id': assignment.get('principal_id', ''),
            'principal_type': assignment.get('principal_type', ''),
            'principal_name': assignment.get('principal_name', ''),
            'principal_display_name': assignment.get('principal_display_name', ''),
            'principal_email': assignment.get('principal_email', ''),
            'permission_set_arn': assignment.get('permission_set_arn', ''),
            'permission_set_name': assignment.get('permission_set_name', ''),
            'assignment_status': assignment.get('assignment_status', ''),
            'matched': matched_value,
            
            # Last-accessed tracking data
            'last_accessed': assignment.get('last_accessed', ''),
            'last_accessed_principal_user': assignment.get('last_accessed_principal_user', ''),
            'days_since_last_access': assignment.get('days_since_last_access', ''),
            'accessed_in_last_x_days': assignment.get('accessed_in_last_x_days'),
            'access_threshold_days': assignment.get('access_threshold_days', ''),
            'access_tracking_updated': assignment.get('access_tracking_updated', ''),
            
            # Timestamps
            'instance_last_updated': instance_data.get('last_updated', ''),
            'application_last_updated': app_data.get('last_updated', ''),
            'assignment_last_updated': assignment.get('last_updated', '')
        }
        
        comprehensive_data.append(record)
    
    # Add applications without assignments
    apps_with_assignments = set(a.get('application_arn') for a in assignments)
    instances_with_apps = set()

    for app in applications:
        app_arn = app['application_arn']
        instance_arn = app.get('instance_arn')
        instances_with_apps.add(instance_arn)

        # Check if this application already has assignment records
        if app_arn not in apps_with_assignments:
            instance_data = instances_by_arn.get(instance_arn, {})
            portal_options = app.get('portal_options', {})
            sign_in_options = portal_options.get('SignInOptions', portal_options.get('sign_in_options', {}))

            record = {
                # Instance data
                'instance_arn': instance_data.get('instance_arn', instance_arn),
                'instance_type': instance_data.get('instance_type', ''),
                'instance_status': instance_data.get('status', ''),
                'identity_store_id': instance_data.get('identity_store_id', ''),
                'account_id': instance_data.get('account_id', app.get('account_id', '')),
                'region': instance_data.get('region', app.get('region', '')),

                # Application data
                'application_arn': app['application_arn'],
                'application_name': app.get('name', ''),
                'application_description': app.get('description', ''),
                'application_status': app.get('status', ''),
                'application_provider_arn': app.get('application_provider_arn', ''),
                'portal_visibility': portal_options.get('Visibility', portal_options.get('visibility', '')),
                'sign_in_origin': sign_in_options.get('Origin', sign_in_options.get('origin', '')),
                'application_url': sign_in_options.get('ApplicationUrl', sign_in_options.get('application_url', '')),

                # No assignment data
                'assignment_id': '',
                'principal_id': '',
                'principal_type': '',
                'principal_name': '',
                'principal_display_name': '',
                'principal_email': '',
                'permission_set_arn': '',
                'permission_set_name': '',
                'assignment_status': '',
                'matched': '',

                # No last-accessed tracking data for apps without assignments
                'last_accessed': '',
                'last_accessed_principal_user': '',
                'days_since_last_access': '',
                'accessed_in_last_x_days': '',
                'access_threshold_days': '',
                'access_tracking_updated': '',

                # Timestamps
                'instance_last_updated': instance_data.get('last_updated', ''),
                'application_last_updated': app.get('last_updated', ''),
                'assignment_last_updated': ''
            }

            comprehensive_data.append(record)

    # Add instances without any applications (ensures all discovered instances appear in the export)
    for inst in instances:
        instance_arn = inst.get('instance_arn')
        if instance_arn not in instances_with_apps:
            record = {
                'instance_arn': instance_arn,
                'instance_type': inst.get('instance_type', ''),
                'instance_status': inst.get('status', ''),
                'identity_store_id': inst.get('identity_store_id', ''),
                'account_id': inst.get('account_id', ''),
                'region': inst.get('region', ''),
                'application_arn': '',
                'application_name': '',
                'application_description': '',
                'application_status': '',
                'application_provider_arn': '',
                'portal_visibility': '',
                'sign_in_origin': '',
                'application_url': '',
                'assignment_id': '',
                'principal_id': '',
                'principal_type': '',
                'principal_name': '',
                'principal_display_name': '',
                'principal_email': '',
                'permission_set_arn': '',
                'permission_set_name': '',
                'assignment_status': '',
                'matched': '',
                'last_accessed': '',
                'last_accessed_principal_user': '',
                'days_since_last_access': '',
                'accessed_in_last_x_days': '',
                'access_threshold_days': '',
                'access_tracking_updated': '',
                'instance_last_updated': inst.get('last_updated', ''),
                'application_last_updated': '',
                'assignment_last_updated': ''
            }
            comprehensive_data.append(record)

    return comprehensive_data

def generate_filter_suffix(filters: Dict[str, Any]) -> str:
    """
    Generate filename suffix based on applied filters
    
    Args:
        filters: Dictionary of filter criteria
        
    Returns:
        String suffix for filename
    """
    suffix_parts = []
    
    if filters.get('account_id'):
        suffix_parts.append(f"account_{filters['account_id']}")
    
    if filters.get('region'):
        suffix_parts.append(f"region_{filters['region']}")
    
    if filters.get('application_name'):
        # Clean application name for filename
        clean_name = ''.join(c for c in filters['application_name'] if c.isalnum() or c in '-_')
        suffix_parts.append(f"app_{clean_name}")
    
    if filters.get('principal_type'):
        suffix_parts.append(f"type_{filters['principal_type'].lower()}")
    
    if filters.get('date_from') or filters.get('date_to'):
        date_from = filters.get('date_from', 'start')
        date_to = filters.get('date_to', 'end')
        suffix_parts.append(f"dates_{date_from}_to_{date_to}")
    
    if suffix_parts:
        return f"_{'_'.join(suffix_parts)}"
    
    return ""

def generate_s3_key(filename: str, export_type: str, filters: Dict[str, Any]) -> str:
    """
    Generate S3 key with organized structure
    
    Args:
        filename: Base filename
        export_type: Type of export (applications, assignments, full)
        filters: Applied filters
        
    Returns:
        S3 key with organized path structure
    """
    # Create date-based folder structure
    now = datetime.now(timezone.utc)
    year = now.strftime('%Y')
    month = now.strftime('%m')
    day = now.strftime('%d')
    
    # Create account-based subfolder if account filter is applied
    account_folder = ""
    if filters.get('account_id'):
        account_folder = f"account-{filters['account_id']}/"
    
    # Construct S3 key with hierarchical structure
    s3_key = f"{S3_PREFIX}/{export_type}/{year}/{month}/{day}/{account_folder}{filename}"
    
    return s3_key

def upload_to_s3(csv_data: str, s3_key: str) -> int:
    """
    Upload CSV data to S3 with metadata and lifecycle management
    
    Args:
        csv_data: CSV content as string
        s3_key: S3 object key
        
    Returns:
        File size in bytes
    """
    try:
        # Calculate file size
        csv_bytes = csv_data.encode('utf-8')
        file_size = len(csv_bytes)
        
        # Prepare metadata
        metadata = {
            'generated-at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'content-type': 'text/csv',
            'file-size': str(file_size)
        }
        
        # Upload with metadata and server-side encryption
        s3_client.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=csv_bytes,
            ContentType='text/csv',
            ContentDisposition=f'attachment; filename="{s3_key.split("/")[-1]}"',
            Metadata=metadata,
            ServerSideEncryption='aws:kms'
        )
        
        # Add tags separately using put_object_tagging
        try:
            s3_client.put_object_tagging(
                Bucket=S3_BUCKET,
                Key=s3_key,
                Tagging={
                    'TagSet': [
                        {'Key': 'Purpose', 'Value': 'IAM-Identity-Center-Export'},
                        {'Key': 'AutoDelete', 'Value': 'true'},
                        {'Key': 'RetentionDays', 'Value': '7'}
                    ]
                }
            )
        except ClientError as tag_error:
            logger.warning(f"Failed to add tags to S3 object {s3_key}: {tag_error}")
            # Continue without tags - not critical for functionality
        
        logger.info(f"Successfully uploaded CSV to S3: {s3_key} ({file_size} bytes)")
        return file_size
        
    except ClientError as e:
        logger.error(f"Error uploading to S3: {e}")
        raise

def generate_presigned_url(s3_key: str, expiration: int = PRESIGNED_URL_EXPIRY_SECONDS) -> str:
    """
    Generate secure pre-signed URL for S3 object download
    
    Args:
        s3_key: S3 object key
        expiration: URL expiration time in seconds (default 15 minutes)
        
    Returns:
        Pre-signed download URL
    """
    try:
        # Ensure expiration is within AWS limits (max 7 days = 604800 seconds)
        if expiration > 604800:
            expiration = 604800
        
        # Generate pre-signed URL with minimal parameters to avoid signature issues
        url = s3_client.generate_presigned_url(
            'get_object',
            Params={
                'Bucket': S3_BUCKET, 
                'Key': s3_key
            },
            ExpiresIn=expiration,
            HttpMethod='GET'
        )
        
        logger.info(f"Generated pre-signed URL for {s3_key} (expires in {expiration}s)")
        return url
        
    except ClientError as e:
        logger.error(f"Error generating pre-signed URL: {e}")
        raise

def cleanup_old_exports() -> None:
    """
    Clean up old export files from S3 (called periodically)
    This function removes exports older than 7 days to manage storage costs
    """
    try:
        # Calculate cutoff date (7 days ago)
        cutoff_date = datetime.now(timezone.utc).timestamp() - (7 * 24 * 3600)
        
        # List objects in the exports prefix
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=S3_BUCKET, Prefix=S3_PREFIX)
        
        objects_to_delete = []
        
        for page in pages:
            for obj in page.get('Contents', []):
                # Check if object is older than cutoff
                if obj['LastModified'].timestamp() < cutoff_date:
                    objects_to_delete.append({'Key': obj['Key']})
        
        # Delete old objects in batches
        if objects_to_delete:
            # Process in batches of 1000 (S3 delete limit)
            for i in range(0, len(objects_to_delete), 1000):
                batch = objects_to_delete[i:i+1000]
                
                s3_client.delete_objects(
                    Bucket=S3_BUCKET,
                    Delete={'Objects': batch}
                )
                
                logger.info(f"Deleted {len(batch)} old export files")
        
        logger.info(f"Cleanup completed. Removed {len(objects_to_delete)} old files")
        
    except ClientError as e:
        logger.warning(f"Error during cleanup: {e}")
        # Don't raise - cleanup failures shouldn't break exports

def get_export_statistics() -> Dict[str, Any]:
    """
    Get statistics about stored exports
    
    Returns:
        Dictionary with export statistics
    """
    try:
        # List all objects in exports prefix
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=S3_BUCKET, Prefix=S3_PREFIX)
        
        total_files = 0
        total_size = 0
        export_types = {}
        
        for page in pages:
            for obj in page.get('Contents', []):
                total_files += 1
                total_size += obj['Size']
                
                # Extract export type from key
                key_parts = obj['Key'].split('/')
                if len(key_parts) > 1:
                    export_type = key_parts[1]  # exports/{type}/...
                    export_types[export_type] = export_types.get(export_type, 0) + 1
        
        return {
            'total_files': total_files,
            'total_size_bytes': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'export_types': export_types,
            'last_checked': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }
        
    except ClientError as e:
        logger.error(f"Error getting export statistics: {e}")
        return {
            'error': str(e),
            'last_checked': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        }