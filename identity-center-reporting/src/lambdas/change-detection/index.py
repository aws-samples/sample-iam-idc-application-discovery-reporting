"""
Lambda function for detecting changes in IAM Identity Center resources
"""
import json
import boto3
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

# Import shared modules
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.incremental import IncrementalDiscoveryManager, ChangeRecord, IncrementalDiscoveryState
from shared.monitoring import DiscoveryMonitor
from shared.utils import setup_logging, handle_api_error

logger = setup_logging(__name__)

# Initialize SNS client
sns_client = boto3.client('sns')

# SNS topic ARNs will be read at runtime from environment

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for change detection
    """
    try:
        # Log identifiers and shape only. The event carries the full discovery
        # result set, and assignment records include principal_display_name and
        # principal_email, so serialising it duplicates the organisation's user
        # roster into CloudWatch on every run.
        logger.info(
            "Starting change detection: action=%s discovery_run_id=%s result_count=%s",
            event.get("action"),
            event.get("discovery_run_id"),
            len(event.get("application_results", []) or []),
        )
        
        # Handle flatten_applications action
        action = event.get('action')
        if action == 'flatten_applications':
            return flatten_applications(event)

        # Handle the incremental-eligibility check invoked by the discovery
        # state machine's CheckIncrementalEligibility step. This must return
        # body.should_run_incremental for the EvaluateIncrementalDecision
        # Choice state that follows it.
        if action == 'check_eligibility':
            return check_incremental_discovery_eligibility(event, context)

        discovery_run_id = event.get('discovery_run_id')
        if not discovery_run_id:
            raise ValueError("discovery_run_id is required")
        
        # Initialize managers
        incremental_manager = IncrementalDiscoveryManager()
        monitor = DiscoveryMonitor()
        
        # Get discovery type
        discovery_type = event.get('discovery_type', 'full')
        
        if discovery_type == 'incremental':
            return handle_incremental_discovery(event, incremental_manager, monitor)
        else:
            return handle_full_discovery_change_detection(event, incremental_manager, monitor)
    
    except Exception as e:
        logger.error(f"Error in change detection: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'success': False,
                'error': str(e),
                'discovery_run_id': event.get('discovery_run_id')
            }
        }

def flatten_applications(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten nested application arrays from map results
    """
    try:
        application_results = event.get('application_results', [])
        discovery_run_id = event.get('discovery_run_id')
        
        # Flatten the nested arrays
        flattened_applications = []
        for result in application_results:
            if isinstance(result, dict) and 'Payload' in result:
                payload = result['Payload']
                if isinstance(payload, dict) and 'applications' in payload:
                    applications = payload['applications']
                    if isinstance(applications, list):
                        flattened_applications.extend(applications)
        
        logger.info(f"Flattened {len(flattened_applications)} applications from {len(application_results)} results")
        
        return {
            'success': True,
            'applications': flattened_applications,
            'discovery_run_id': discovery_run_id,
            'count': len(flattened_applications)
        }
    
    except Exception as e:
        logger.error(f"Error flattening applications: {str(e)}")
        return {
            'success': False,
            'applications': [],
            'error': str(e),
            'discovery_run_id': event.get('discovery_run_id')
        }

def handle_incremental_discovery(event: Dict[str, Any], 
                               incremental_manager: IncrementalDiscoveryManager,
                               monitor: DiscoveryMonitor) -> Dict[str, Any]:
    """Handle incremental discovery change detection"""
    
    discovery_run_id = event['discovery_run_id']
    logger.info(f"Processing incremental discovery for run {discovery_run_id}")
    
    try:
        # Check if incremental discovery should run
        should_run_incremental, reason = incremental_manager.should_run_incremental_discovery(
            force_full=event.get('force_full_discovery', False)
        )
        
        if not should_run_incremental:
            logger.info(f"Incremental discovery not recommended: {reason}")
            return {
                'statusCode': 200,
                'body': {
                    'should_run_incremental': False,
                    'reason': reason,
                    'discovery_run_id': discovery_run_id,
                    'recommended_action': 'full_discovery'
                }
            }
        
        # Create incremental discovery plan
        incremental_plan = incremental_manager.create_incremental_discovery_plan(discovery_run_id)
        
        logger.info(f"Created incremental discovery plan: {json.dumps(incremental_plan, default=str)}")
        
        return {
            'statusCode': 200,
            'body': {
                'should_run_incremental': True,
                'reason': reason,
                'discovery_run_id': discovery_run_id,
                'incremental_plan': incremental_plan
            }
        }
    
    except Exception as e:
        logger.error(f"Error in incremental discovery planning: {str(e)}")
        monitor.publish_error_metrics('incremental_planning_error', discovery_run_id, str(e))
        raise

def handle_full_discovery_change_detection(event: Dict[str, Any],
                                         incremental_manager: IncrementalDiscoveryManager,
                                         monitor: DiscoveryMonitor) -> Dict[str, Any]:
    """Handle change detection for full discovery results"""
    
    discovery_run_id = event['discovery_run_id']
    logger.info(f"Processing change detection for full discovery run {discovery_run_id}")
    
    try:
        all_changes = []

        # The state machine passes the whole execution state object as
        # discovery_results (discovery_results.$ = "$"), which by the DetectChanges
        # step holds the already-flattened applications under "applications" and the
        # assignment-discovery Map output under "assignment_results". Each Map item
        # is a Lambda invoke result {"Payload": {"statusCode", "body": "<json str>"}}
        # where body is a JSON STRING that must be parsed.
        discovery_results = event.get('discovery_results', {})

        instances = []
        applications = []
        assignments = []

        def _extract_body(item: Any) -> Dict[str, Any]:
            """Return the parsed body dict from a Lambda invoke Map result, or {}."""
            if not isinstance(item, dict):
                return {}
            payload = item.get('Payload', item)
            body = payload.get('body') if isinstance(payload, dict) else None
            if isinstance(body, str):
                try:
                    return json.loads(body)
                except (ValueError, TypeError):
                    return {}
            if isinstance(body, dict):
                return body
            return {}

        if isinstance(discovery_results, dict):
            # Applications are pre-flattened by the ExtractFlattenedApplications step.
            apps = discovery_results.get('applications')
            if isinstance(apps, list):
                applications.extend(apps)

            # Assignment Map results: list of Lambda invoke results.
            for item in discovery_results.get('assignment_results', []) or []:
                body = _extract_body(item)
                if body.get('assignments'):
                    assignments.extend(body['assignments'])

            # Instance scanner result (if propagated).
            for item in discovery_results.get('instance_results', []) or []:
                body = _extract_body(item)
                if body.get('instances'):
                    instances.extend(body['instances'])

        # Detect changes
        if instances:
            logger.info(f"Detecting changes in {len(instances)} instances")
            instance_changes = incremental_manager.detect_instance_changes(instances, discovery_run_id)
            all_changes.extend(instance_changes)
            logger.info(f"Detected {len(instance_changes)} instance changes")
        
        if applications:
            logger.info(f"Detecting changes in {len(applications)} applications")
            app_changes = incremental_manager.detect_application_changes(applications, discovery_run_id)
            all_changes.extend(app_changes)
            logger.info(f"Detected {len(app_changes)} application changes")
        
        if assignments:
            logger.info(f"Detecting changes in {len(assignments)} assignments")
            assignment_changes = incremental_manager.detect_assignment_changes(assignments, discovery_run_id)
            all_changes.extend(assignment_changes)
            logger.info(f"Detected {len(assignment_changes)} assignment changes")
        
        # Save changes
        if all_changes:
            incremental_manager.save_changes(all_changes)
            logger.info(f"Saved {len(all_changes)} changes to change log")
        
        # Update discovery state
        state = IncrementalDiscoveryState(
            discovery_run_id=discovery_run_id,
            total_instances=len(instances),
            total_applications=len(applications),
            total_assignments=len(assignments),
            change_detection_enabled=True
        )
        
        incremental_manager.update_discovery_state(state, is_full_discovery=True)
        
        # Get change summary
        change_summary = incremental_manager.get_change_summary(discovery_run_id)
        
        # Publish metrics
        monitor.publish_phase_metrics('ChangeDetection', discovery_run_id, len(all_changes), 'ChangesDetected')
        
        # Send notifications for significant changes
        if all_changes:
            try:
                send_change_notifications(all_changes, discovery_run_id, change_summary)
            except Exception as e:
                logger.error(f"Failed to send change notifications: {str(e)}")
                # Don't fail the entire process if notifications fail
        
        # Send discovery status notification
        try:
            send_discovery_status_notification(discovery_run_id, len(all_changes), 'completed')
        except Exception as e:
            logger.error(f"Failed to send discovery status notification: {str(e)}")
        
        logger.info(f"Change detection completed. Total changes: {len(all_changes)}")
        
        return {
            'statusCode': 200,
            'body': {
                'success': True,
                'discovery_run_id': discovery_run_id,
                'total_changes': len(all_changes),
                'changes_by_type': {
                    'instances': len([c for c in all_changes if c.resource_type == 'instance']),
                    'applications': len([c for c in all_changes if c.resource_type == 'application']),
                    'assignments': len([c for c in all_changes if c.resource_type == 'assignment'])
                },
                'changes_by_action': {
                    'created': len([c for c in all_changes if c.change_type == 'created']),
                    'updated': len([c for c in all_changes if c.change_type == 'updated']),
                    'deleted': len([c for c in all_changes if c.change_type == 'deleted'])
                },
                'change_summary': change_summary,
                'state_updated': True,
                'notifications_sent': True
            }
        }
    
    except Exception as e:
        logger.error(f"Error in change detection: {str(e)}")
        monitor.publish_error_metrics('change_detection_error', discovery_run_id, str(e))
        raise

def check_incremental_discovery_eligibility(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Separate handler for checking if incremental discovery should run
    This can be called from Step Functions to make the decision
    """
    try:
        # Identifiers only -- see the note above on PII in the event payload.
        logger.info(
            "Checking incremental discovery eligibility: discovery_run_id=%s",
            event.get("discovery_run_id"),
        )
        
        incremental_manager = IncrementalDiscoveryManager()
        
        should_run_incremental, reason = incremental_manager.should_run_incremental_discovery(
            force_full=event.get('force_full_discovery', False)
        )
        
        result = {
            'statusCode': 200,
            'body': {
                'should_run_incremental': should_run_incremental,
                'reason': reason,
                'discovery_run_id': event.get('discovery_run_id')
            }
        }
        
        if should_run_incremental:
            # Create incremental plan
            incremental_plan = incremental_manager.create_incremental_discovery_plan(
                event.get('discovery_run_id')
            )
            result['body']['incremental_plan'] = incremental_plan
        
        logger.info(f"Incremental discovery eligibility result: {json.dumps(result, default=str)}")
        return result
    
    except Exception as e:
        logger.error(f"Error checking incremental discovery eligibility: {str(e)}")
        return {
            'statusCode': 500,
            'body': {
                'should_run_incremental': False,
                'reason': f"Error: {str(e)}",
                'discovery_run_id': event.get('discovery_run_id')
            }
        }

def send_change_notifications(changes: List[ChangeRecord], discovery_run_id: str, change_summary: Dict[str, Any]) -> None:
    """Send SNS notifications for significant changes"""
    
    change_notification_topic_arn = os.environ.get('CHANGE_NOTIFICATION_TOPIC_ARN')
    if not change_notification_topic_arn:
        logger.warning("CHANGE_NOTIFICATION_TOPIC_ARN not configured, skipping change notifications")
        return
    
    # Filter for significant changes (new applications, deleted applications, new assignments)
    significant_changes = [
        c for c in changes 
        if (c.resource_type == 'application' and c.change_type in ['created', 'deleted']) or
           (c.resource_type == 'assignment' and c.change_type == 'created') or
           (c.resource_type == 'instance' and c.change_type in ['created', 'deleted'])
    ]
    
    if not significant_changes:
        logger.info("No significant changes detected, skipping notifications")
        return
    
    # Group changes by type and action
    changes_by_category = {}
    for change in significant_changes:
        category = f"{change.resource_type}_{change.change_type}"
        if category not in changes_by_category:
            changes_by_category[category] = []
        changes_by_category[category].append(change)
    
    # Create notification message
    message_parts = [
        f"IAM Identity Center Discovery Run {discovery_run_id} detected {len(significant_changes)} significant changes:",
        ""
    ]
    
    for category, category_changes in changes_by_category.items():
        resource_type, change_type = category.split('_', 1)
        message_parts.append(f"• {change_type.title()} {resource_type}s: {len(category_changes)}")
        
        # Add details for first few changes
        for i, change in enumerate(category_changes[:5]):  # Limit to first 5 to avoid message size limits
            if resource_type == 'application':
                app_name = change.new_data.get('name') if change.new_data else change.old_data.get('name') if change.old_data else change.resource_id
                message_parts.append(f"  - {app_name}")
            elif resource_type == 'assignment':
                principal_name = change.new_data.get('principal_name') if change.new_data else change.old_data.get('principal_name') if change.old_data else change.resource_id
                message_parts.append(f"  - {principal_name}")
            elif resource_type == 'instance':
                message_parts.append(f"  - {change.resource_id}")
        
        if len(category_changes) > 5:
            message_parts.append(f"  ... and {len(category_changes) - 5} more")
        
        message_parts.append("")
    
    # Add summary information
    message_parts.extend([
        "Summary:",
        f"• Total changes detected: {len(changes)}",
        f"• Discovery run ID: {discovery_run_id}",
        f"• Timestamp: {datetime.now(timezone.utc).isoformat()}",
        "",
        "For detailed change information, check the discovery logs and change history."
    ])
    
    message = "\n".join(message_parts)
    
    # Create subject
    subject = f"IAM Identity Center Changes Detected - {len(significant_changes)} significant changes"
    
    try:
        # Send notification
        response = sns_client.publish(
            TopicArn=change_notification_topic_arn,
            Subject=subject,
            Message=message,
            MessageAttributes={
                'discovery_run_id': {
                    'DataType': 'String',
                    'StringValue': discovery_run_id
                },
                'change_count': {
                    'DataType': 'Number',
                    'StringValue': str(len(significant_changes))
                },
                'notification_type': {
                    'DataType': 'String',
                    'StringValue': 'change_detection'
                }
            }
        )
        
        logger.info(f"Sent change notification for {len(significant_changes)} changes. Message ID: {response['MessageId']}")
        
    except Exception as e:
        logger.error(f"Failed to send change notification: {str(e)}")
        raise

def send_discovery_status_notification(discovery_run_id: str, change_count: int, status: str) -> None:
    """Send SNS notification for discovery status"""
    
    discovery_status_topic_arn = os.environ.get('DISCOVERY_STATUS_TOPIC_ARN')
    if not discovery_status_topic_arn:
        logger.warning("DISCOVERY_STATUS_TOPIC_ARN not configured, skipping status notifications")
        return
    
    # Create status message
    if status == 'completed':
        message = f"""
IAM Identity Center Discovery Run Completed

Discovery Run ID: {discovery_run_id}
Status: {status.title()}
Changes Detected: {change_count}
Completion Time: {datetime.now(timezone.utc).isoformat()}

The discovery process has successfully completed and change detection has been performed.
"""
    elif status == 'failed':
        message = f"""
IAM Identity Center Discovery Run Failed

Discovery Run ID: {discovery_run_id}
Status: {status.title()}
Failure Time: {datetime.now(timezone.utc).isoformat()}

The discovery process encountered an error. Please check the logs for more details.
"""
    else:
        message = f"""
IAM Identity Center Discovery Run Status Update

Discovery Run ID: {discovery_run_id}
Status: {status.title()}
Timestamp: {datetime.now(timezone.utc).isoformat()}
"""
    
    subject = f"IAM Identity Center Discovery {status.title()} - Run {discovery_run_id}"
    
    try:
        # Send notification
        response = sns_client.publish(
            TopicArn=discovery_status_topic_arn,
            Subject=subject,
            Message=message.strip(),
            MessageAttributes={
                'discovery_run_id': {
                    'DataType': 'String',
                    'StringValue': discovery_run_id
                },
                'status': {
                    'DataType': 'String',
                    'StringValue': status
                },
                'change_count': {
                    'DataType': 'Number',
                    'StringValue': str(change_count)
                },
                'notification_type': {
                    'DataType': 'String',
                    'StringValue': 'discovery_status'
                }
            }
        )
        
        logger.info(f"Sent discovery status notification ({status}). Message ID: {response['MessageId']}")
        
    except Exception as e:
        logger.error(f"Failed to send discovery status notification: {str(e)}")
        raise

def create_change_summary_report(changes: List[ChangeRecord], discovery_run_id: str) -> Dict[str, Any]:
    """Create a detailed change summary report for notifications"""
    
    # Group changes by resource type and change type
    summary = {
        'discovery_run_id': discovery_run_id,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'total_changes': len(changes),
        'changes_by_resource_type': {},
        'changes_by_action': {},
        'significant_changes': [],
        'before_after_comparison': {}
    }
    
    # Count changes by resource type
    for change in changes:
        resource_type = change.resource_type
        if resource_type not in summary['changes_by_resource_type']:
            summary['changes_by_resource_type'][resource_type] = 0
        summary['changes_by_resource_type'][resource_type] += 1
    
    # Count changes by action
    for change in changes:
        change_type = change.change_type
        if change_type not in summary['changes_by_action']:
            summary['changes_by_action'][change_type] = 0
        summary['changes_by_action'][change_type] += 1
    
    # Identify significant changes
    for change in changes:
        if (change.resource_type == 'application' and change.change_type in ['created', 'deleted']) or \
           (change.resource_type == 'assignment' and change.change_type == 'created') or \
           (change.resource_type == 'instance' and change.change_type in ['created', 'deleted']):
            
            resource_name = None
            if change.new_data:
                resource_name = change.new_data.get('name') or change.new_data.get('principal_name')
            elif change.old_data:
                resource_name = change.old_data.get('name') or change.old_data.get('principal_name')
            
            summary['significant_changes'].append({
                'resource_type': change.resource_type,
                'change_type': change.change_type,
                'resource_id': change.resource_id,
                'resource_name': resource_name,
                'timestamp': change.detected_at.isoformat() if change.detected_at else None,
                'old_data': change.old_data,
                'new_data': change.new_data
            })
    
    return summary