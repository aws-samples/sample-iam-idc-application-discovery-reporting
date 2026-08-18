"""
Main Lambda handler for Identity Center application assignment monitoring.

This module orchestrates the event-driven validation and remediation workflow
for Identity Center application assignments.
"""

import os
import traceback
from typing import Dict, Any, Optional
from datetime import datetime, timezone

# Import all required modules
from event_parser import parse_event, EventParsingError
from validation import validate_assignment
from config import load_config, ConfigurationError
from remediation import should_trigger_remediation, get_remediation_action
from deletion import delete_application_assignment
from identity_center_client import IdentityCenterClient, IdentityCenterClientError
from identity_store_client import IdentityStoreClient, IdentityStoreClientError
from sns_client import SNSClient, send_notification
from structured_logging import (
    get_logger,
    log_lambda_invocation,
    log_event_parsing,
    log_validation_result,
    log_remediation_action,
    log_deletion_attempt,
    log_deletion_result,
    log_notification_sent,
    log_error,
    log_processing_complete
)
from error_handler import (
    handle_global_exception,
    format_error_notification_message,
    build_error_subject_line,
    categorize_error,
    determine_severity
)


def get_application_name(application_arn: str, ic_client: IdentityCenterClient) -> str:
    """Get application name from Identity Center, fallback to ARN on error."""
    try:
        # List applications and find by ARN
        instance_arn = f"arn:aws:sso:::instance/{application_arn.split('/')[1]}"
        apps = ic_client.list_applications_for_instance(instance_arn)
        for app in apps:
            if app.get('ApplicationArn') == application_arn:
                return app.get('Name', application_arn)
        return application_arn
    except Exception:
        return application_arn


def get_principal_name(
    principal_id: str,
    principal_type: str,
    identity_store_id: str,
    is_client: IdentityStoreClient
) -> str:
    """
    Get principal (user or group) name from Identity Store API.
    
    Args:
        principal_id: ID of the principal
        principal_type: Type of principal (USER or GROUP)
        identity_store_id: Identity Store ID (directory ID)
        is_client: Identity Store client instance
        
    Returns:
        Principal display name, or principal_id if name cannot be retrieved
    """
    try:
        if not identity_store_id:
            log_error(
                error_message="Identity Store ID is empty, cannot resolve principal name",
                error_type="MissingIdentityStoreId",
                stage="principal_lookup",
                principalId=principal_id,
                principalType=principal_type
            )
            return principal_id
            
        if principal_type == 'GROUP':
            response = is_client.describe_group(identity_store_id, principal_id)
            display_name = response.get('DisplayName', principal_id)
            if display_name == principal_id:
                log_error(
                    error_message="Group DisplayName not found in API response, using group ID",
                    error_type="MissingDisplayName",
                    stage="principal_lookup",
                    principalId=principal_id,
                    principalType=principal_type
                )
            return display_name
        elif principal_type == 'USER':
            response = is_client.describe_user(identity_store_id, principal_id)
            # Try DisplayName first, fall back to UserName
            display_name = response.get('DisplayName') or response.get('UserName', principal_id)
            if display_name == principal_id:
                log_error(
                    error_message="User DisplayName/UserName not found in API response, using user ID",
                    error_type="MissingDisplayName",
                    stage="principal_lookup",
                    principalId=principal_id,
                    principalType=principal_type
                )
            return display_name
        else:
            return principal_id
    except Exception as e:
        # If we can't get the name, use the principal_id
        log_error(
            error_message=f"Failed to get principal name: {str(e)}",
            error_type=type(e).__name__,
            stage="principal_lookup",
            principalId=principal_id,
            principalType=principal_type,
            identityStoreId=identity_store_id
        )
        return principal_id


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """
    Main Lambda handler function for Identity Center application assignment monitoring.
    
    This function:
    1. Parses incoming EventBridge event
    2. Extracts CloudTrail event details
    3. Validates that group name is included in application name
    4. Determines remediation action based on configuration
    5. Executes remediation (delete or notify only)
    6. Sends SNS notification
    7. Logs all steps with structured logging
    
    Args:
        event: EventBridge event containing CloudTrail details
        context: Lambda context object
        
    Returns:
        Dictionary with processing status and details
    """
    start_time = datetime.now(timezone.utc)
    logger = get_logger()
    
    # Initialize variables for tracking
    parsed_data = None
    validation_result = None
    action_taken = "NONE"
    processing_success = False
    names_unresolved = False
    
    try:
        # Step 1: Log Lambda invocation
        log_lambda_invocation(event, context)
        
        # Step 2: Load configuration
        try:
            config = load_config()
            logger.info(
                "Configuration loaded",
                stage="configuration",
                enableAutoDeletion=config.enable_auto_deletion,
                snsTopicArn=config.sns_topic_arn
            )
        except ConfigurationError as e:
            log_error(
                error_message=str(e),
                error_type="ConfigurationError",
                stage="configuration"
            )
            raise
        
        # Step 2b: Reject events that did not originate from the SSO EventBridge
        # rule. This is defense-in-depth against accidental/naive direct
        # invocation — a determined caller with lambda:InvokeFunction controls
        # these fields too, so the authoritative control is restricting who
        # holds lambda:InvokeFunction on this function (see the stack's
        # resource policy). In auto-deletion mode a crafted event could
        # otherwise trigger sso:DeleteApplicationAssignment.
        if event.get('source') != 'aws.sso' or event.get('detail-type') != 'AWS API Call via CloudTrail':
            log_error(
                error_message="Rejected event: not from the expected aws.sso EventBridge source",
                error_type="UntrustedInvocationSource",
                stage="event_classification"
            )
            return {
                'statusCode': 403,
                'body': 'Event rejected: untrusted invocation source',
                'action': 'REJECTED'
            }

        # Step 3: Parse event
        try:
            parsed_data = parse_event(event)
            log_event_parsing(success=True, parsed_data=parsed_data)
        except EventParsingError as e:
            log_event_parsing(success=False, error=str(e))

            # Re-raise so the async invocation fails and the unparseable (poison)
            # event is captured by the SQS dead-letter queue for inspection,
            # rather than being silently acknowledged. The global exception
            # handler below sends the single error notification (categorized,
            # severity-rated) — avoiding a duplicate alert for the same event.
            raise
        
        # Step 4: Initialize clients
        ic_client = IdentityCenterClient()
        is_client = IdentityStoreClient()
        
        # Step 5: Check event type and determine if validation is needed
        event_name = parsed_data.get('event_name', '')
        
        # Events that don't require validation (audit trail only)
        audit_only_events = [
            'DeleteApplicationAssignment',
            'DeleteProfile',
            'DisassociateProfile'
        ]
        
        # Profile events that need validation
        profile_validation_events = [
            'AssociateProfile'  # Validates profile associations using application resolution
        ]
        
        # Profile events that don't need validation (audit only)
        profile_audit_events = [
            'CreateProfile',
            'UpdateProfile'
        ]

        # Assignment-configuration events. These carry no principal, so the
        # group-name-vs-application-name check does not apply. They are alerted
        # on instead: assignmentRequired=false opens the application to every
        # user in the identity store with no assignment involved.
        assignment_config_events = [
            'PutApplicationAssignmentConfiguration'
        ]

        # Get identity store ID from parsed data (for name resolution).
        # Application-assignment CloudTrail events do not carry directoryId, so
        # fall back to resolving it from the configured instance ARN.
        identity_store_id = parsed_data.get('directory_id', '')
        if not identity_store_id:
            instance_arn_env = os.environ.get('IDENTITY_CENTER_INSTANCE_ARN', '')
            if instance_arn_env:
                identity_store_id = ic_client.get_identity_store_id(instance_arn_env)
        
        # Resolve names based on event type
        if event_name in assignment_config_events:
            # No principal on this event -- resolve the application only.
            application_name = get_application_name(
                parsed_data['application_arn'],
                ic_client
            ) if parsed_data.get('application_arn') else "N/A"

            assignment_required = parsed_data.get('assignment_required')
            # Treat only an explicit False as the risky transition. An absent
            # value means CloudTrail did not record it; do not infer "open"
            # from a missing field.
            opens_to_all = assignment_required is False
            action = "ASSIGNMENT_REQUIRED_DISABLED" if opens_to_all else "AUDIT_LOG"

            logger.info(
                "Assignment configuration change detected",
                stage="event_classification",
                eventName=event_name,
                applicationName=application_name,
                assignmentRequired=assignment_required,
                action=action
            )

            sns_client = SNSClient(config.sns_topic_arn)
            try:
                send_notification(
                    sns_client=sns_client,
                    application_name=application_name,
                    group_name="N/A",
                    account_id=parsed_data['account_id'],
                    action=action,
                    status="SUCCESS",
                    application_arn=parsed_data['application_arn'],
                    principal_id="N/A",
                    error_message=(
                        "assignmentRequired was set to false: this application is "
                        "now reachable by every user in the identity store without "
                        "an application assignment."
                    ) if opens_to_all else None,
                    timestamp=parsed_data.get('event_time'),
                    user_identity=parsed_data.get('user_identity')
                )
                log_notification_sent(
                    success=True,
                    action=action,
                    status="SUCCESS",
                    application_name=application_name,
                    group_name="N/A"
                )
            except Exception as sns_error:
                log_notification_sent(
                    success=False,
                    action=action,
                    status="SUCCESS",
                    error=str(sns_error)
                )

            processing_success = True
            end_time = datetime.now(timezone.utc)
            duration_ms = (end_time - start_time).total_seconds() * 1000
            log_processing_complete(
                success=True, action_taken=action, duration_ms=duration_ms
            )

            return {
                'statusCode': 200,
                'body': f'Assignment configuration change logged: {event_name}',
                'action': action
            }

        if event_name in profile_validation_events:
            # For AssociateProfile, we need to resolve both group and application names
            # The profile is associated with applications, so we need to find them
            
            # Get principal (group) name
            principal_name = get_principal_name(
                parsed_data['principal_id'],
                parsed_data['principal_type'],
                identity_store_id,
                is_client
            )
            
            # Get the application ARN from the instance and profile
            # Use the configured instance ARN from environment variable
            instance_arn = os.environ.get('IDENTITY_CENTER_INSTANCE_ARN', '')
            instance_id = parsed_data.get('instance_id', '')
            profile_id = parsed_data.get('profile_id', '')
            account_id = parsed_data.get('account_id', '')
            
            application_arn = None
            application_name = None
            
            if instance_arn and instance_id and profile_id:
                try:
                    # Get the application that uses this profile
                    # Note: For Identity Center, applications are in the management account
                    # The management account ID should be extracted from the instance ARN or configured
                    app_info = ic_client.get_application_from_instance_and_profile(
                        instance_arn,
                        instance_id,
                        profile_id
                    )
                    
                    if app_info:
                        application_arn = app_info.get('ApplicationArn')
                        application_name = app_info.get('Name', 'Unknown')
                        logger.info(
                            "Retrieved application for profile",
                            stage="name_lookup",
                            applicationArn=application_arn,
                            applicationName=application_name,
                            profileId=profile_id,
                            instanceId=instance_id
                        )
                    else:
                        log_error(
                            error_message="Could not find application for profile",
                            error_type="ApplicationNotFound",
                            stage="name_lookup",
                            profileId=profile_id,
                            instanceId=instance_id
                        )
                        application_name = f"Profile-{profile_id}"
                except Exception as e:
                    log_error(
                        error_message=f"Error getting application from profile: {str(e)}",
                        error_type=type(e).__name__,
                        stage="name_lookup",
                        profileId=profile_id,
                        instanceId=instance_id
                    )
                    application_name = f"Profile-{profile_id}"
            else:
                application_name = f"Profile-{profile_id}"

            logger.info(
                "Retrieved names for profile association",
                stage="name_lookup",
                applicationName=application_name,
                principalName=principal_name,
                profileId=profile_id
            )

            # We'll validate using the resolved names
            group_name = principal_name

            # Fail closed for the profile path too: a "Profile-<id>" fallback
            # application name (or an unresolved principal) is never a real
            # name, so any non-compliant verdict from it is untrustworthy —
            # without this, a transient SSO/Identity Store failure during an
            # AssociateProfile event would auto-delete a legitimate assignment.
            names_unresolved = (
                not identity_store_id
                or application_name == f"Profile-{profile_id}"
                or group_name == parsed_data['principal_id']
            )
            
        elif event_name in profile_audit_events:
            # Profile creation/update events - audit only, no validation
            application_name = f"Profile-{parsed_data.get('profile_id', 'Unknown')}"
            group_name = parsed_data['principal_id']
            
        elif event_name in audit_only_events:
            # Resolve names for audit logging
            if parsed_data['application_arn']:
                application_name = get_application_name(
                    parsed_data['application_arn'],
                    ic_client
                )
            else:
                application_name = "N/A"
            
            if identity_store_id and parsed_data['principal_id']:
                group_name = get_principal_name(
                    parsed_data['principal_id'],
                    parsed_data['principal_type'],
                    identity_store_id,
                    is_client
                )
            else:
                group_name = parsed_data.get('principal_id', 'N/A')
            
            # Log the event but don't validate or remediate
            logger.info(
                "Audit-only event detected - logging without validation",
                stage="event_classification",
                eventName=event_name,
                applicationName=application_name,
                groupName=group_name
            )
            
            # Send notification for audit trail
            sns_client = SNSClient(config.sns_topic_arn)
            try:
                send_notification(
                    sns_client=sns_client,
                    application_name=application_name,
                    group_name=group_name,
                    account_id=parsed_data['account_id'],
                    action="AUDIT_LOG",
                    status="SUCCESS",
                    application_arn=parsed_data['application_arn'],
                    principal_id=parsed_data['principal_id'],
                    error_message=None,
                    timestamp=parsed_data.get('event_time'),
                    user_identity=parsed_data.get('user_identity')
                )
                log_notification_sent(
                    success=True,
                    action="AUDIT_LOG",
                    status="SUCCESS",
                    application_name=application_name,
                    group_name=group_name
                )
            except Exception as sns_error:
                log_notification_sent(
                    success=False,
                    action="AUDIT_LOG",
                    status="SUCCESS",
                    error=str(sns_error)
                )
            
            processing_success = True
            end_time = datetime.now(timezone.utc)
            duration_ms = (end_time - start_time).total_seconds() * 1000
            log_processing_complete(success=True, action_taken="AUDIT_LOG", duration_ms=duration_ms)
            
            return {
                'statusCode': 200,
                'body': f'Audit event logged: {event_name}',
                'action': 'AUDIT_LOG'
            }
        
        if event_name in profile_audit_events:
            # Log profile events but don't validate assignments
            logger.info(
                "Profile event detected - logging for future enhancement",
                stage="event_classification",
                eventName=event_name,
                applicationName=application_name
            )
            
            processing_success = True
            end_time = datetime.now(timezone.utc)
            duration_ms = (end_time - start_time).total_seconds() * 1000
            log_processing_complete(success=True, action_taken="PROFILE_EVENT_LOGGED", duration_ms=duration_ms)
            
            return {
                'statusCode': 200,
                'body': f'Profile event logged: {event_name}',
                'action': 'PROFILE_EVENT_LOGGED'
            }
        
        # For regular application assignment events, resolve names
        if event_name not in profile_validation_events:
            application_name = get_application_name(
                parsed_data['application_arn'],
                ic_client
            )
            
            group_name = get_principal_name(
                parsed_data['principal_id'],
                parsed_data['principal_type'],
                identity_store_id,
                is_client
            )

            logger.info(
                "Retrieved application and group names",
                stage="name_lookup",
                applicationName=application_name,
                groupName=group_name
            )

            # Fail closed: if either name could not be resolved (the resolver
            # fell back to the raw ARN/ID, or the Identity Store ID was empty),
            # we cannot trust a non-compliant verdict. A GUID is never a
            # substring of an application name, so an unresolved name would
            # otherwise be auto-deleted as "non-compliant". Force
            # notification-only so a transient lookup failure can never revoke
            # legitimate access.
            names_unresolved = (
                not identity_store_id
                or application_name == parsed_data['application_arn']
                or group_name == parsed_data['principal_id']
            )

        # USER assignments are exempt: the naming convention binds GROUP names
        # to application names. A user's display name is essentially never a
        # substring of an application name, so validating users would flag —
        # and in auto-remediation mode delete — every direct user assignment.
        if parsed_data.get('principal_type') == 'USER':
            logger.info(
                "User assignments are exempt from compliance validation",
                stage="event_classification",
                eventName=event_name,
                applicationName=application_name,
                principalName=group_name
            )
            processing_success = True
            end_time = datetime.now(timezone.utc)
            duration_ms = (end_time - start_time).total_seconds() * 1000
            log_processing_complete(success=True, action_taken="USER_EXEMPT", duration_ms=duration_ms)
            return {
                'statusCode': 200,
                'body': 'User assignment exempt from compliance validation',
                'action': 'USER_EXEMPT'
            }

        # Step 6: Validate assignment (for Create/Update events and AssociateProfile)
        validation_result = validate_assignment(application_name, group_name, config.group_name_regex)
        log_validation_result(validation_result, application_name, group_name)
        
        # Step 7: Determine if remediation is needed
        if not should_trigger_remediation(validation_result):
            # Assignment is compliant - no action needed
            action_taken = "NONE"
            log_remediation_action(
                action=action_taken,
                validation_result=validation_result,
                enable_auto_deletion=config.enable_auto_deletion
            )
            
            processing_success = True
            
            # Calculate duration
            end_time = datetime.now(timezone.utc)
            duration_ms = (end_time - start_time).total_seconds() * 1000
            
            log_processing_complete(
                success=True,
                action_taken=action_taken,
                duration_ms=duration_ms
            )
            
            return {
                'statusCode': 200,
                'body': 'Assignment is compliant - no action taken',
                'action': action_taken
            }
        
        # Step 8: Determine remediation action
        action_taken = get_remediation_action(
            validation_result,
            config.enable_auto_deletion
        )

        # Fail closed: never auto-delete on an unverified verdict. If name
        # resolution failed, downgrade DELETED to NOTIFICATION_ONLY so a
        # transient Identity Store/SSO lookup error cannot revoke access.
        if names_unresolved and action_taken == "DELETED":
            log_error(
                error_message="Name resolution failed; downgrading auto-deletion to notification to avoid wrongful deletion",
                error_type="UnresolvedNamesFailClosed",
                stage="remediation_decision",
                applicationArn=parsed_data.get('application_arn'),
                principalId=parsed_data.get('principal_id')
            )
            action_taken = "NOTIFICATION_ONLY"

        log_remediation_action(
            action=action_taken,
            validation_result=validation_result,
            enable_auto_deletion=config.enable_auto_deletion
        )
        
        # Step 9: Execute remediation if auto-deletion is enabled
        deletion_result = None
        deletion_status = "SUCCESS"
        deletion_error = None
        
        if action_taken == "DELETED":
            # Attempt deletion
            log_deletion_attempt(
                application_arn=parsed_data['application_arn'],
                principal_id=parsed_data['principal_id'],
                principal_type=parsed_data['principal_type']
            )
            
            deletion_result = delete_application_assignment(
                application_arn=parsed_data['application_arn'],
                principal_id=parsed_data['principal_id'],
                principal_type=parsed_data['principal_type'],
                client=ic_client
            )
            
            log_deletion_result(deletion_result)
            
            # Update status based on deletion result
            if not deletion_result.success:
                deletion_status = "FAILED"
                deletion_error = deletion_result.error_message
        
        # Step 10: Send SNS notification
        sns_client = SNSClient(config.sns_topic_arn)
        
        try:
            send_notification(
                sns_client=sns_client,
                application_name=application_name,
                group_name=group_name,
                account_id=parsed_data['account_id'],
                action=action_taken,
                status=deletion_status,
                application_arn=parsed_data['application_arn'],
                principal_id=parsed_data['principal_id'],
                error_message=deletion_error,
                timestamp=parsed_data.get('event_time'),
                user_identity=parsed_data.get('user_identity')
            )
            
            log_notification_sent(
                success=True,
                action=action_taken,
                status=deletion_status,
                application_name=application_name,
                group_name=group_name
            )
        except Exception as sns_error:
            log_notification_sent(
                success=False,
                action=action_taken,
                status=deletion_status,
                application_name=application_name,
                group_name=group_name,
                error=str(sns_error)
            )
            # Don't fail the entire process if notification fails
            logger.error(
                "SNS notification failed but continuing",
                stage="notification",
                error=str(sns_error)
            )
        
        # Mark processing as successful
        processing_success = True
        
        # Calculate duration
        end_time = datetime.now(timezone.utc)
        duration_ms = (end_time - start_time).total_seconds() * 1000
        
        log_processing_complete(
            success=True,
            action_taken=action_taken,
            duration_ms=duration_ms
        )
        
        return {
            'statusCode': 200,
            'body': 'Processing completed successfully',
            'action': action_taken,
            'status': deletion_status
        }
    
    except Exception as e:
        # Global exception handler
        log_error(
            error_message=str(e),
            error_type=type(e).__name__,
            stage="global_handler",
            stackTrace=traceback.format_exc()
        )
        
        # Handle unexpected exception
        error_info = handle_global_exception(e, event, parsed_data)
        
        # Try to send error notification
        try:
            config = load_config()
            sns_client = SNSClient(config.sns_topic_arn)
            
            error_category = categorize_error(e)
            severity = determine_severity(error_category)
            subject = build_error_subject_line(error_category, severity)
            message = format_error_notification_message(error_info['error'])
            
            sns_client.publish_message(subject=subject, message=message)
            log_notification_sent(
                success=True,
                action="ERROR",
                status="FAILED",
                error=str(e)
            )
        except Exception as sns_error:
            # If we can't send notification, just log it
            log_notification_sent(
                success=False,
                action="ERROR",
                status="FAILED",
                error=str(sns_error)
            )
        
        # Calculate duration
        end_time = datetime.now(timezone.utc)
        duration_ms = (end_time - start_time).total_seconds() * 1000
        
        log_processing_complete(
            success=False,
            action_taken=action_taken,
            duration_ms=duration_ms
        )

        # Re-raise so the asynchronous (EventBridge) invocation is recorded as a
        # failure. This is what drives Lambda's async retries and ultimately the
        # SQS dead-letter queue — returning a dict here would mark the invocation
        # successful and the DLQ would never receive the failed event.
        raise
