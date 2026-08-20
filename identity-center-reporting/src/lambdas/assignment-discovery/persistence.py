# Assignment data persistence with incremental updates and change detection

import logging
import boto3
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from shared.models import Assignment, DiscoveryResult, ValidationError
from shared.utils import query_all, redact_assignment_id

logger = logging.getLogger(__name__)

def persist_assignments_with_change_detection(
    assignments: List[Assignment], 
    table_name: str
) -> DiscoveryResult:
    """
    Persist assignments to DynamoDB with incremental updates and change detection
    
    Args:
        assignments: List of Assignment objects to persist
        table_name: DynamoDB table name
    
    Returns:
        DiscoveryResult indicating success/failure of persistence operations
    """
    result = DiscoveryResult()
    
    try:
        # Create DynamoDB client
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)
        
        logger.info(f"Persisting {len(assignments)} assignments with change detection")
        
        # Process assignments with change detection
        new_assignments = []
        updated_assignments = []
        unchanged_assignments = []
        
        for assignment in assignments:
            try:
                # Check if assignment already exists
                existing_item = get_existing_assignment(table, assignment.assignment_id)
                
                if existing_item:
                    # Check if update is needed
                    if should_update_assignment(existing_item, assignment):
                        updated_assignments.append(assignment)
                    else:
                        unchanged_assignments.append(assignment)
                        result.add_data(assignment)  # Count as successful
                else:
                    new_assignments.append(assignment)
                    
            except Exception as e:
                error_msg = f"Error checking assignment {redact_assignment_id(assignment.assignment_id)}: {str(e)}"
                logger.warning(error_msg)
                result.add_error(error_msg)
                continue
        
        # Persist new assignments
        if new_assignments:
            new_result = persist_assignment_batch_with_validation(table, new_assignments, "NEW")
            result.data.extend(new_result.data)
            result.errors.extend(new_result.errors)
            if not new_result.success:
                result.success = False
        
        # Persist updated assignments
        if updated_assignments:
            update_result = persist_assignment_batch_with_validation(table, updated_assignments, "UPDATED")
            result.data.extend(update_result.data)
            result.errors.extend(update_result.errors)
            if not update_result.success:
                result.success = False
        
        # Log summary
        logger.info(
            f"Assignment persistence summary: "
            f"{len(new_assignments)} new, "
            f"{len(updated_assignments)} updated, "
            f"{len(unchanged_assignments)} unchanged"
        )
        
        if result.success:
            result.message = (
                f"Successfully persisted {len(result.data)} assignments "
                f"({len(new_assignments)} new, {len(updated_assignments)} updated)"
            )
        else:
            result.message = (
                f"Persistence completed with errors. "
                f"{len(result.data)} successful, {len(result.errors)} errors"
            )
        
    except Exception as e:
        error_msg = f"Failed to persist assignments with change detection: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result

def get_existing_assignment(table: boto3.resource, assignment_id: str) -> Optional[Dict[str, Any]]:
    """
    Get existing assignment from DynamoDB
    
    Args:
        table: DynamoDB table resource
        assignment_id: Assignment ID (primary key)
    
    Returns:
        Existing item dictionary or None if not found
    """
    try:
        response = table.get_item(
            Key={'assignment_id': assignment_id}
        )
        return response.get('Item')
        
    except Exception as e:
        logger.debug(f"Error checking existing assignment {redact_assignment_id(assignment_id)}: {str(e)}")
        return None

def should_update_assignment(existing_item: Dict[str, Any], new_assignment: Assignment) -> bool:
    """
    Determine if an existing assignment should be updated based on change detection
    
    Args:
        existing_item: Existing DynamoDB item
        new_assignment: New assignment data
    
    Returns:
        True if update is needed, False otherwise
    """
    try:
        new_item = new_assignment.to_dict()
        
        # Fields to compare for changes
        compare_fields = [
            'principal_name', 
            'permission_set_arn', 
            'permission_set_name',
            'assignment_status',
            'account_id',
            'instance_arn'
        ]
        
        for field in compare_fields:
            existing_value = existing_item.get(field)
            new_value = new_item.get(field)
            
            if existing_value != new_value:
                # Log which field changed, never the values. This loop compares
                # every field including principal_name, so interpolating the
                # before/after values put resolved Identity Store display names --
                # email addresses, for a directory federated from an email-based
                # source -- into CloudWatch at debug level.
                logger.debug(
                    "Change detected in assignment %s field '%s'",
                    redact_assignment_id(new_assignment.assignment_id), field
                )
                return True
        
        # Check if principal was previously deleted but now exists
        existing_name = existing_item.get('principal_name', '')
        new_name = new_item.get('principal_name', '')
        
        if '[DELETED' in existing_name and '[DELETED' not in new_name:
            # The fact worth recording is that a principal came back, not who it
            # is -- and the assignment ID is not the neutral record locator it looks
            # like: it is "<application-id>#<principal-id>", so emitting it whole
            # here would restate the very UUID principal_name is redacted for, at
            # info level, where retention is longest.
            logger.info(
                "Principal restored for assignment %s (previously marked deleted)",
                redact_assignment_id(new_assignment.assignment_id)
            )
            return True
        
        return False
        
    except Exception as e:
        logger.debug(f"Error comparing assignments, defaulting to update: {str(e)}")
        return True  # Default to update on error

def persist_assignment_batch_with_validation(
    table: boto3.resource, 
    assignments: List[Assignment], 
    operation_type: str
) -> DiscoveryResult:
    """
    Persist a batch of assignments to DynamoDB with validation
    
    Args:
        table: DynamoDB table resource
        assignments: List of Assignment objects to persist
        operation_type: Type of operation (NEW, UPDATED)
    
    Returns:
        DiscoveryResult for the batch operation
    """
    result = DiscoveryResult()
    
    try:
        logger.info(f"Persisting {len(assignments)} {operation_type} assignments")
        
        # Prepare batch write items
        with table.batch_writer() as batch:
            for assignment in assignments:
                try:
                    # Validate assignment before writing
                    assignment.validate()
                    
                    # Convert to DynamoDB item format with proper indexing
                    item = prepare_assignment_item_with_indexes(assignment, operation_type)
                    
                    # Write to DynamoDB with upsert logic
                    batch.put_item(Item=item)
                    result.add_data(assignment)
                    
                    logger.debug(f"Queued {operation_type} assignment for batch write: {redact_assignment_id(assignment.assignment_id)}")
                    
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
        
        logger.info(f"Batch write completed for {len(result.data)} {operation_type} assignments")
        
    except Exception as e:
        error_msg = f"Batch write failed for {operation_type} assignments: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result

def prepare_assignment_item_with_indexes(assignment: Assignment, operation_type: str) -> Dict[str, Any]:
    """
    Prepare assignment data for DynamoDB storage with proper indexing
    
    Args:
        assignment: Assignment object to prepare
        operation_type: Type of operation (NEW, UPDATED)
    
    Returns:
        Dictionary formatted for DynamoDB storage with GSI attributes
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
        'operation_type': operation_type,
        'version': '1.0'
    }
    
    # Add GSI attributes for efficient querying
    # GSI 1: application_arn-index for application-based queries
    item['gsi1_pk'] = assignment.application_arn
    item['gsi1_sk'] = f"{assignment.principal_type}#{assignment.principal_id}"
    
    # GSI 2: principal_id-index for user/group-based queries
    item['gsi2_pk'] = assignment.principal_id
    item['gsi2_sk'] = assignment.application_arn
    
    # GSI 3: instance_arn-index for instance-based queries
    if assignment.instance_arn:
        item['gsi3_pk'] = assignment.instance_arn
        item['gsi3_sk'] = f"{assignment.application_arn}#{assignment.principal_id}"
    
    # Add composite keys for relationship mapping
    item['composite_keys'] = {
        'app_principal': f"{assignment.application_arn}#{assignment.principal_id}",
        'instance_app': f"{assignment.instance_arn}#{assignment.application_arn}" if assignment.instance_arn else None,
        'account_app': f"{assignment.account_id}#{assignment.application_arn}" if assignment.account_id else None
    }
    
    # Remove None values to save space
    item = {k: v for k, v in item.items() if v is not None}
    
    return item

def cleanup_stale_assignments(
    table_name: str, 
    application_arn: str, 
    current_assignments: List[Assignment]
) -> DiscoveryResult:
    """
    Clean up assignments that no longer exist for an application
    
    Args:
        table_name: DynamoDB table name
        application_arn: Application ARN to clean up
        current_assignments: List of current assignments
    
    Returns:
        DiscoveryResult indicating cleanup results
    """
    result = DiscoveryResult()
    
    try:
        # Create DynamoDB client
        dynamodb = boto3.resource('dynamodb')
        table = dynamodb.Table(table_name)
        
        logger.info(f"Cleaning up stale assignments for application: {application_arn}")
        
        # Get all existing assignments for the application
        existing_assignments = query_assignments_by_application(table, application_arn)
        
        # Create set of current assignment IDs
        current_assignment_ids = {assignment.assignment_id for assignment in current_assignments}
        
        # Find assignments to delete
        assignments_to_delete = []
        for existing in existing_assignments:
            if existing['assignment_id'] not in current_assignment_ids:
                assignments_to_delete.append(existing)
        
        # Delete stale assignments
        if assignments_to_delete:
            delete_result = delete_assignment_batch(table, assignments_to_delete)
            result.data.extend(delete_result.data)
            result.errors.extend(delete_result.errors)
            if not delete_result.success:
                result.success = False
            
            logger.info(f"Deleted {len(delete_result.data)} stale assignments")
        else:
            logger.info("No stale assignments found")
        
        result.message = f"Cleanup completed. Deleted {len(result.data)} stale assignments"
        
    except Exception as e:
        error_msg = f"Failed to cleanup stale assignments: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result

def query_assignments_by_application(table: boto3.resource, application_arn: str) -> List[Dict[str, Any]]:
    """
    Query all assignments for a specific application using GSI
    
    Args:
        table: DynamoDB table resource
        application_arn: Application ARN
    
    Returns:
        List of assignment items
    """
    try:
        # Paginated: this list drives stale-assignment cleanup, so a truncated
        # first page leaves revoked assignments in the table where they are then
        # exported as live access.
        return query_all(
            table,
            IndexName='application_arn-index',
            KeyConditionExpression=boto3.dynamodb.conditions.Key('gsi1_pk').eq(application_arn)
        )
        
    except Exception as e:
        logger.error(f"Error querying assignments by application {application_arn}: {str(e)}")
        return []

def delete_assignment_batch(table: boto3.resource, assignments_to_delete: List[Dict[str, Any]]) -> DiscoveryResult:
    """
    Delete a batch of assignments from DynamoDB
    
    Args:
        table: DynamoDB table resource
        assignments_to_delete: List of assignment items to delete
    
    Returns:
        DiscoveryResult for the delete operation
    """
    result = DiscoveryResult()
    
    try:
        with table.batch_writer() as batch:
            for assignment in assignments_to_delete:
                try:
                    batch.delete_item(
                        Key={'assignment_id': assignment['assignment_id']}
                    )
                    result.add_data(assignment)
                    logger.debug(f"Queued assignment for deletion: {redact_assignment_id(assignment['assignment_id'])}")
                    
                except Exception as e:
                    error_msg = f"Error deleting assignment {redact_assignment_id(assignment.get('assignment_id'))}: {str(e)}"
                    logger.warning(error_msg)
                    result.add_error(error_msg)
                    continue
        
        logger.info(f"Batch delete completed for {len(result.data)} assignments")
        
    except Exception as e:
        error_msg = f"Batch delete failed: {str(e)}"
        logger.error(error_msg)
        result.add_error(error_msg)
    
    return result