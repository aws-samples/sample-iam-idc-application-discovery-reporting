"""
Incremental discovery logic for IAM Identity Center Discovery
"""
import boto3
import json
import os
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, asdict

from .utils import scan_all, query_all, redact_assignment_id
from boto3.dynamodb.conditions import Key, Attr

def _redact_resource_id(resource_type: str, resource_id: str) -> str:
    """
    A resource_id that is safe to log, given what kind of resource it names.

    ChangeRecord.resource_id is polymorphic: an instance or application ARN, or --
    for an assignment -- "<application-id>#<principal-id>", which carries the
    Identity Store UUID. Logging the field uniformly leaks the assignment case;
    redacting it uniformly truncates the ARN cases down to eight characters and
    makes the error message useless. The type is right there on the record, so
    branch on it.
    """
    if resource_type == 'assignment':
        return redact_assignment_id(resource_id)
    return resource_id


@dataclass
class ChangeRecord:
    """Record of a change detected during incremental discovery"""
    resource_type: str  # 'instance', 'application', 'assignment'
    resource_id: str
    change_type: str  # 'created', 'updated', 'deleted'
    old_data: Optional[Dict[str, Any]] = None
    new_data: Optional[Dict[str, Any]] = None
    detected_at: Optional[datetime] = None
    discovery_run_id: Optional[str] = None

@dataclass
class IncrementalDiscoveryState:
    """State information for incremental discovery"""
    last_full_discovery: Optional[datetime] = None
    last_incremental_discovery: Optional[datetime] = None
    discovery_run_id: Optional[str] = None
    total_instances: int = 0
    total_applications: int = 0
    total_assignments: int = 0
    change_detection_enabled: bool = True

class IncrementalDiscoveryManager:
    """Manage incremental discovery operations"""
    
    def __init__(self, region_name: str = 'us-east-1'):
        self.dynamodb = boto3.resource('dynamodb', region_name=region_name)
        # Table names come from environment variables set by the CDK stack so
        # the manager binds to the real deployed tables rather than placeholder
        # logical names.
        self.instances_table = self.dynamodb.Table(
            os.environ.get('INSTANCES_TABLE', 'iam-identity-center-instances'))
        self.applications_table = self.dynamodb.Table(
            os.environ.get('APPLICATIONS_TABLE', 'iam-identity-center-applications'))
        self.assignments_table = self.dynamodb.Table(
            os.environ.get('ASSIGNMENTS_TABLE', 'iam-identity-center-assignments'))

        # State and change-log tables for tracking discovery runs
        self.state_table_name = os.environ.get(
            'DISCOVERY_STATE_TABLE', 'iam-identity-center-discovery-state')
        self.change_log_table_name = os.environ.get(
            'DISCOVERY_CHANGE_LOG_TABLE', 'iam-identity-center-discovery-change-log')
        self.state_table = self.dynamodb.Table(self.state_table_name)

        self.changes: List[ChangeRecord] = []
    
    def should_run_incremental_discovery(self, force_full: bool = False) -> Tuple[bool, str]:
        """Determine if incremental discovery should run"""
        if force_full:
            return False, "Full discovery requested"
        
        try:
            state = self.get_discovery_state()
            
            if not state.last_full_discovery:
                return False, "No previous full discovery found"
            
            # Check if it's been more than 24 hours since last full discovery
            if state.last_full_discovery < datetime.now(timezone.utc) - timedelta(hours=24):
                return False, "Full discovery required (>24 hours since last full)"
            
            # Check if incremental discovery is enabled
            if not state.change_detection_enabled:
                return False, "Change detection disabled"
            
            return True, "Incremental discovery recommended"
            
        except Exception as e:
            return False, f"Error checking discovery state: {str(e)}"
    
    def get_discovery_state(self) -> IncrementalDiscoveryState:
        """Get current discovery state"""
        try:
            response = self.state_table.get_item(
                Key={'state_id': 'current'}
            )
            
            if 'Item' in response:
                item = response['Item']
                return IncrementalDiscoveryState(
                    last_full_discovery=datetime.fromisoformat(item.get('last_full_discovery')) if item.get('last_full_discovery') else None,
                    last_incremental_discovery=datetime.fromisoformat(item.get('last_incremental_discovery')) if item.get('last_incremental_discovery') else None,
                    discovery_run_id=item.get('discovery_run_id'),
                    total_instances=item.get('total_instances', 0),
                    total_applications=item.get('total_applications', 0),
                    total_assignments=item.get('total_assignments', 0),
                    change_detection_enabled=item.get('change_detection_enabled', True)
                )
            else:
                return IncrementalDiscoveryState()
                
        except Exception as e:
            print(f"Error getting discovery state: {str(e)}")
            return IncrementalDiscoveryState()
    
    def update_discovery_state(self, state: IncrementalDiscoveryState, 
                             is_full_discovery: bool = False) -> None:
        """Update discovery state"""
        try:
            now = datetime.now(timezone.utc)
            
            item = {
                'state_id': 'current',
                'discovery_run_id': state.discovery_run_id,
                'total_instances': state.total_instances,
                'total_applications': state.total_applications,
                'total_assignments': state.total_assignments,
                'change_detection_enabled': state.change_detection_enabled,
                'updated_at': now.isoformat()
            }
            
            if is_full_discovery:
                item['last_full_discovery'] = now.isoformat()
            else:
                item['last_incremental_discovery'] = now.isoformat()
                if state.last_full_discovery:
                    item['last_full_discovery'] = state.last_full_discovery.isoformat()
            
            self.state_table.put_item(Item=item)
            
        except Exception as e:
            print(f"Error updating discovery state: {str(e)}")
    
    def detect_instance_changes(self, current_instances: List[Dict[str, Any]], 
                              discovery_run_id: str) -> List[ChangeRecord]:
        """Detect changes in instances"""
        changes = []
        
        try:
            # Get existing instances
            existing_instances = {item['instance_arn']: item
                                  for item in scan_all(self.instances_table)
                                  if not item.get('retired_at')}
            
            current_instance_arns = {instance['instance_arn'] for instance in current_instances}
            existing_instance_arns = set(existing_instances.keys())
            
            # Detect new instances
            new_instances = current_instance_arns - existing_instance_arns
            for instance_arn in new_instances:
                instance_data = next(i for i in current_instances if i['instance_arn'] == instance_arn)
                changes.append(ChangeRecord(
                    resource_type='instance',
                    resource_id=instance_arn,
                    change_type='created',
                    new_data=instance_data,
                    detected_at=datetime.now(timezone.utc),
                    discovery_run_id=discovery_run_id
                ))
            
            # Detect deleted instances
            deleted_instances = existing_instance_arns - current_instance_arns
            for instance_arn in deleted_instances:
                changes.append(ChangeRecord(
                    resource_type='instance',
                    resource_id=instance_arn,
                    change_type='deleted',
                    old_data=existing_instances[instance_arn],
                    detected_at=datetime.now(timezone.utc),
                    discovery_run_id=discovery_run_id
                ))
            
            # Detect updated instances
            for instance in current_instances:
                instance_arn = instance['instance_arn']
                if instance_arn in existing_instances:
                    existing = existing_instances[instance_arn]
                    if self._has_significant_changes(existing, instance, ['status', 'identity_store_id']):
                        changes.append(ChangeRecord(
                            resource_type='instance',
                            resource_id=instance_arn,
                            change_type='updated',
                            old_data=existing,
                            new_data=instance,
                            detected_at=datetime.now(timezone.utc),
                            discovery_run_id=discovery_run_id
                        ))
            
        except Exception as e:
            print(f"Error detecting instance changes: {str(e)}")
        
        return changes
    
    def detect_application_changes(self, current_applications: List[Dict[str, Any]], 
                                 discovery_run_id: str) -> List[ChangeRecord]:
        """Detect changes in applications"""
        changes = []
        
        try:
            # Get existing applications
            existing_applications = {item['application_arn']: item
                                     for item in scan_all(self.applications_table)
                                     if not item.get('retired_at')}
            
            current_app_arns = {app['application_arn'] for app in current_applications}
            existing_app_arns = set(existing_applications.keys())
            
            # Detect new applications
            new_applications = current_app_arns - existing_app_arns
            for app_arn in new_applications:
                app_data = next(a for a in current_applications if a['application_arn'] == app_arn)
                changes.append(ChangeRecord(
                    resource_type='application',
                    resource_id=app_arn,
                    change_type='created',
                    new_data=app_data,
                    detected_at=datetime.now(timezone.utc),
                    discovery_run_id=discovery_run_id
                ))
            
            # Detect deleted applications
            deleted_applications = existing_app_arns - current_app_arns
            for app_arn in deleted_applications:
                changes.append(ChangeRecord(
                    resource_type='application',
                    resource_id=app_arn,
                    change_type='deleted',
                    old_data=existing_applications[app_arn],
                    detected_at=datetime.now(timezone.utc),
                    discovery_run_id=discovery_run_id
                ))
            
            # Detect updated applications
            for app in current_applications:
                app_arn = app['application_arn']
                if app_arn in existing_applications:
                    existing = existing_applications[app_arn]
                    if self._has_significant_changes(existing, app, ['status', 'description', 'portal_options']):
                        changes.append(ChangeRecord(
                            resource_type='application',
                            resource_id=app_arn,
                            change_type='updated',
                            old_data=existing,
                            new_data=app,
                            detected_at=datetime.now(timezone.utc),
                            discovery_run_id=discovery_run_id
                        ))
            
        except Exception as e:
            print(f"Error detecting application changes: {str(e)}")
        
        return changes
    
    def detect_assignment_changes(self, current_assignments: List[Dict[str, Any]], 
                                discovery_run_id: str) -> List[ChangeRecord]:
        """Detect changes in assignments"""
        changes = []
        
        try:
            # Get existing assignments
            existing_assignments = {item['assignment_id']: item
                                    for item in scan_all(self.assignments_table)
                                    if not item.get('retired_at')}
            
            current_assignment_ids = {assignment['assignment_id'] for assignment in current_assignments}
            existing_assignment_ids = set(existing_assignments.keys())
            
            # Detect new assignments
            new_assignments = current_assignment_ids - existing_assignment_ids
            for assignment_id in new_assignments:
                assignment_data = next(a for a in current_assignments if a['assignment_id'] == assignment_id)
                changes.append(ChangeRecord(
                    resource_type='assignment',
                    resource_id=assignment_id,
                    change_type='created',
                    new_data=assignment_data,
                    detected_at=datetime.now(timezone.utc),
                    discovery_run_id=discovery_run_id
                ))
            
            # Detect deleted assignments
            deleted_assignments = existing_assignment_ids - current_assignment_ids
            for assignment_id in deleted_assignments:
                changes.append(ChangeRecord(
                    resource_type='assignment',
                    resource_id=assignment_id,
                    change_type='deleted',
                    old_data=existing_assignments[assignment_id],
                    detected_at=datetime.now(timezone.utc),
                    discovery_run_id=discovery_run_id
                ))
            
            # Detect updated assignments
            for assignment in current_assignments:
                assignment_id = assignment['assignment_id']
                if assignment_id in existing_assignments:
                    existing = existing_assignments[assignment_id]
                    if self._has_significant_changes(existing, assignment, ['assignment_status', 'principal_name', 'permission_set_name']):
                        changes.append(ChangeRecord(
                            resource_type='assignment',
                            resource_id=assignment_id,
                            change_type='updated',
                            old_data=existing,
                            new_data=assignment,
                            detected_at=datetime.now(timezone.utc),
                            discovery_run_id=discovery_run_id
                        ))
            
        except Exception as e:
            print(f"Error detecting assignment changes: {str(e)}")
        
        return changes
    
    def _has_significant_changes(self, old_data: Dict[str, Any], 
                               new_data: Dict[str, Any], 
                               fields_to_check: List[str]) -> bool:
        """Check if there are significant changes between old and new data"""
        for field in fields_to_check:
            old_value = old_data.get(field)
            new_value = new_data.get(field)
            
            if old_value != new_value:
                return True
        
        return False
    
    def get_resources_to_process(self, changes: List[ChangeRecord]) -> Dict[str, Set[str]]:
        """Get resources that need to be processed based on changes"""
        resources_to_process = {
            'instances': set(),
            'applications': set(),
            'assignments': set()
        }
        
        for change in changes:
            if change.resource_type == 'instance':
                resources_to_process['instances'].add(change.resource_id)
                # If instance changed, need to reprocess its applications
                try:
                    apps = query_all(
                        self.applications_table,
                        IndexName='instance_arn-index',
                        KeyConditionExpression=Key('instance_arn').eq(change.resource_id)
                    )
                    for app in apps:
                        resources_to_process['applications'].add(app['application_arn'])
                except Exception as e:
                    print(f"Error getting applications for instance {_redact_resource_id(change.resource_type, change.resource_id)}: {str(e)}")
            
            elif change.resource_type == 'application':
                resources_to_process['applications'].add(change.resource_id)
                # If application changed, need to reprocess its assignments
                try:
                    assignments = query_all(
                        self.assignments_table,
                        IndexName='application_arn-index',
                        KeyConditionExpression=Key('application_arn').eq(change.resource_id)
                    )
                    for assignment in assignments:
                        resources_to_process['assignments'].add(assignment['assignment_id'])
                except Exception as e:
                    print(f"Error getting assignments for application {_redact_resource_id(change.resource_type, change.resource_id)}: {str(e)}")
            
            elif change.resource_type == 'assignment':
                resources_to_process['assignments'].add(change.resource_id)
        
        return resources_to_process
    
    def create_incremental_discovery_plan(self, discovery_run_id: str) -> Dict[str, Any]:
        """
        Report the scope of the next discovery run.

        This does NOT narrow the work. The counts below are the full current
        inventory, and every discovery Lambda re-enumerates all instances,
        applications, and assignments regardless of what this plan says. The
        fields are named to reflect that: 'scope' is the full inventory and
        'narrowing_strategy' is 'none'.

        The previous version reported the same full counts under
        'estimated_scope' with 'optimization_strategy': 'timestamp_based',
        which read in CloudWatch as though a timestamp-bounded subset had been
        selected.

        The plan is not unused -- it is passed but unread. change-detection
        returns it under body.incremental_plan, the state machine's
        InitializeIncrementalDiscovery state forwards it into
        IncrementalInstanceScanner's payload, and instance-scanner then ignores
        it: that Lambda does not reference incremental_plan or discovery_type at
        all. So the wiring exists end to end and narrows nothing, which is why
        the field names matter -- the label was the only thing claiming an
        optimization existed.

        To make the run genuinely incremental, feed detected changes through
        get_resources_to_process() and pass the resulting id sets to the
        discovery Lambdas as an explicit work list. That is a behavioural
        change and is deliberately not done here.
        """
        state = self.get_discovery_state()

        return {
            'discovery_run_id': discovery_run_id,
            'discovery_type': 'incremental',
            'last_full_discovery': state.last_full_discovery.isoformat() if state.last_full_discovery else None,
            'last_incremental_discovery': state.last_incremental_discovery.isoformat() if state.last_incremental_discovery else None,
            'change_detection_enabled': state.change_detection_enabled,
            'scope': {
                'instances_to_check': state.total_instances,
                'applications_to_check': state.total_applications,
                'assignments_to_check': state.total_assignments,
                'scope_is_full_inventory': True
            },
            'narrowing_strategy': 'none'
        }
    
    def save_changes(self, changes: List[ChangeRecord]) -> None:
        """Save detected changes to a change log table"""
        if not changes:
            return
        
        try:
            # Create change log table if it doesn't exist
            change_log_table = self.dynamodb.Table(self.change_log_table_name)
            
            with change_log_table.batch_writer() as batch:
                for change in changes:
                    item = asdict(change)
                    # Convert datetime to string for DynamoDB
                    if item['detected_at']:
                        item['detected_at'] = item['detected_at'].isoformat()
                    
                    # Create a unique ID for the change record
                    item['change_id'] = f"{change.discovery_run_id}#{change.resource_type}#{change.resource_id}#{change.change_type}"
                    
                    batch.put_item(Item=item)
            
        except Exception as e:
            print(f"Error saving changes: {str(e)}")

    def retire_deleted_resources(self, changes: List[ChangeRecord]) -> int:
        """
        Stamp retired_at on rows whose deletion has just been recorded.

        Deletion is detected by set difference: a row present in DynamoDB but absent
        from the current enumeration. Nothing used to act on that verdict, so the row
        stayed and every subsequent run re-derived the same difference and wrote
        another change-log record. Observed in a live account: 8 genuinely deleted
        resources produced 89 change-log records, one of them re-reported 27 times.
        The applications table also kept over-reporting (19 rows for 17 live
        applications), so the CSV exports inherited the same drift.

        retired_at marks the row as already-accounted-for rather than removing it.
        Deleting outright would discard the audit trail this solution exists to
        provide, and would turn any partial enumeration into permanent data loss;
        the detection baselines skip retired rows, so a retired resource is reported
        exactly once. If the resource later reappears, discovery's put_item rewrites
        the row without retired_at, and it is correctly reported as created again.

        Call this only after save_changes has persisted the records. Retiring first
        would let a failed write drop the deletion from the audit trail with no
        second chance to notice it.

        Args:
            changes: the change records that were just persisted.

        Returns:
            Number of rows successfully stamped.
        """
        retired_at = datetime.now(timezone.utc).isoformat()

        # instances and assignments are single-key tables; applications is keyed on
        # (application_arn, instance_arn), so the range key has to come off the row
        # the detector captured in old_data.
        targets = {
            'instance': (self.instances_table, lambda d: {'instance_arn': d['instance_arn']}),
            'application': (self.applications_table,
                            lambda d: {'application_arn': d['application_arn'],
                                       'instance_arn': d['instance_arn']}),
            'assignment': (self.assignments_table, lambda d: {'assignment_id': d['assignment_id']}),
        }

        stamped = 0
        for change in changes:
            if change.change_type != 'deleted':
                continue
            target = targets.get(change.resource_type)
            if not target or not change.old_data:
                continue
            table, build_key = target
            try:
                table.update_item(
                    Key=build_key(change.old_data),
                    UpdateExpression='SET retired_at = :t',
                    ExpressionAttributeValues={':t': retired_at},
                )
                stamped += 1
            except Exception as e:
                # A row that cannot be stamped is re-reported next run, which is the
                # pre-existing behaviour -- noisy, not wrong. Failing the whole
                # discovery over it would be worse.
                print(f"Error retiring {change.resource_type} {_redact_resource_id(change.resource_type, change.resource_id)}: {str(e)}")

        return stamped

    def get_change_summary(self, discovery_run_id: str) -> Dict[str, Any]:
        """Get summary of changes for a discovery run"""
        try:
            change_log_table = self.dynamodb.Table(self.change_log_table_name)
            
            changes = scan_all(
                change_log_table,
                FilterExpression=Attr('discovery_run_id').eq(discovery_run_id)
            )
            
            summary = {
                'discovery_run_id': discovery_run_id,
                'total_changes': len(changes),
                'changes_by_type': {},
                'changes_by_resource': {},
                'generated_at': datetime.now(timezone.utc).isoformat()
            }
            
            for change in changes:
                change_type = change['change_type']
                resource_type = change['resource_type']
                
                if change_type not in summary['changes_by_type']:
                    summary['changes_by_type'][change_type] = 0
                summary['changes_by_type'][change_type] += 1
                
                if resource_type not in summary['changes_by_resource']:
                    summary['changes_by_resource'][resource_type] = 0
                summary['changes_by_resource'][resource_type] += 1
            
            return summary
            
        except Exception as e:
            print(f"Error getting change summary: {str(e)}")
            return {}

def create_incremental_discovery_state_machine_fragment() -> Dict[str, Any]:
    """Create Step Functions fragment for incremental discovery logic"""
    
    return {
        "CheckDiscoveryType": {
            "Type": "Choice",
            "Comment": "Determine if this should be full or incremental discovery",
            "Choices": [
                {
                    "Variable": "$.force_full_discovery",
                    "BooleanEquals": True,
                    "Next": "FullDiscoveryPath"
                },
                {
                    "Variable": "$.incremental_discovery_enabled",
                    "BooleanEquals": True,
                    "Next": "CheckLastDiscoveryTime"
                }
            ],
            "Default": "FullDiscoveryPath"
        },
        "CheckLastDiscoveryTime": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": {
                "FunctionName": "${IncrementalDiscoveryCheckFunction}",
                "Payload.$": "$"
            },
            "Next": "EvaluateIncrementalDecision"
        },
        "EvaluateIncrementalDecision": {
            "Type": "Choice",
            "Comment": "Decide between full and incremental discovery",
            "Choices": [
                {
                    "Variable": "$.Payload.body.should_run_incremental",
                    "BooleanEquals": True,
                    "Next": "IncrementalDiscoveryPath"
                }
            ],
            "Default": "FullDiscoveryPath"
        },
        "IncrementalDiscoveryPath": {
            "Type": "Pass",
            "Comment": "Set up for incremental discovery",
            "Parameters": {
                "discovery_type": "incremental",
                "discovery_run_id.$": "$.discovery_run_id",
                "incremental_plan.$": "$.Payload.body.incremental_plan"
            },
            "Next": "IncrementalParallelDiscovery"
        },
        "FullDiscoveryPath": {
            "Type": "Pass",
            "Comment": "Set up for full discovery",
            "Parameters": {
                "discovery_type": "full",
                "discovery_run_id.$": "$.discovery_run_id"
            },
            "Next": "ParallelDiscovery"
        },
        "IncrementalParallelDiscovery": {
            "Type": "Parallel",
            "Comment": "Run incremental discovery with change detection",
            "Branches": [
                {
                    "StartAt": "IncrementalOrganizationScanner",
                    "States": {
                        "IncrementalOrganizationScanner": {
                            "Type": "Task",
                            "Resource": "arn:aws:states:::lambda:invoke",
                            "Parameters": {
                                "FunctionName": "${OrganizationScannerFunction}",
                                "Payload": {
                                    "discovery_type": "incremental",
                                    "discovery_run_id.$": "$.discovery_run_id",
                                    "incremental_plan.$": "$.incremental_plan"
                                }
                            },
                            "End": True
                        }
                    }
                }
            ],
            "Next": "ProcessIncrementalResults"
        },
        "ProcessIncrementalResults": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": {
                "FunctionName": "${ChangeDetectionFunction}",
                "Payload.$": "$"
            },
            "Next": "PublishChangeMetrics"
        },
        "PublishChangeMetrics": {
            "Type": "Task",
            "Resource": "arn:aws:states:::aws-sdk:cloudwatch:putMetricData",
            "Parameters": {
                "Namespace": "IAMIdentityCenter/Discovery",
                "MetricData": [
                    {
                        "MetricName": "IncrementalChangesDetected",
                        "Value.$": "$.Payload.body.total_changes",
                        "Unit": "Count"
                    },
                    {
                        "MetricName": "IncrementalDiscoveryCompleted",
                        "Value": 1,
                        "Unit": "Count"
                    }
                ]
            },
            "End": True
        }
    }