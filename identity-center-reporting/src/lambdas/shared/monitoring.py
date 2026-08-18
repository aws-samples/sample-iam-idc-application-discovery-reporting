"""
CloudWatch monitoring utilities for IAM Identity Center Discovery
"""
import boto3
import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

@dataclass
class DiscoveryMetrics:
    """Data class for discovery metrics"""
    discovery_run_id: str
    instances_discovered: int = 0
    applications_discovered: int = 0
    assignments_discovered: int = 0
    errors_encountered: int = 0
    start_time: Optional[datetime] = None
    completion_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    phase: str = "initialization"
    progress_percentage: float = 0.0

class DiscoveryMonitor:
    """CloudWatch monitoring for discovery operations"""
    
    def __init__(self, region_name: str = 'us-east-1'):
        self.cloudwatch = boto3.client('cloudwatch', region_name=region_name)
        self.namespace = 'IAMIdentityCenter/Discovery'
    
    def publish_discovery_started(self, discovery_run_id: str) -> None:
        """Publish discovery started metric"""
        self._put_metric_data([
            {
                'MetricName': 'DiscoveryStarted',
                'Value': 1,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': discovery_run_id
                    }
                ]
            }
        ])
    
    def publish_progress_update(self, metrics: DiscoveryMetrics) -> None:
        """Publish progress update metrics"""
        metric_data = [
            {
                'MetricName': 'DiscoveryProgress',
                'Value': metrics.progress_percentage,
                'Unit': 'Percent',
                'Dimensions': [
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': metrics.discovery_run_id
                    },
                    {
                        'Name': 'Phase',
                        'Value': metrics.phase
                    }
                ]
            },
            {
                'MetricName': 'InstancesDiscovered',
                'Value': metrics.instances_discovered,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': metrics.discovery_run_id
                    }
                ]
            },
            {
                'MetricName': 'ApplicationsDiscovered',
                'Value': metrics.applications_discovered,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': metrics.discovery_run_id
                    }
                ]
            },
            {
                'MetricName': 'AssignmentsDiscovered',
                'Value': metrics.assignments_discovered,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': metrics.discovery_run_id
                    }
                ]
            }
        ]
        
        if metrics.errors_encountered > 0:
            metric_data.append({
                'MetricName': 'ErrorsEncountered',
                'Value': metrics.errors_encountered,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': metrics.discovery_run_id
                    }
                ]
            })
        
        self._put_metric_data(metric_data)
    
    def publish_discovery_completed(self, metrics: DiscoveryMetrics) -> None:
        """Publish discovery completion metrics"""
        metric_data = [
            {
                'MetricName': 'DiscoveryCompleted',
                'Value': 1,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': metrics.discovery_run_id
                    }
                ]
            },
            {
                'MetricName': 'DiscoveryProgress',
                'Value': 100,
                'Unit': 'Percent',
                'Dimensions': [
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': metrics.discovery_run_id
                    }
                ]
            }
        ]
        
        if metrics.duration_seconds:
            metric_data.append({
                'MetricName': 'DiscoveryDuration',
                'Value': metrics.duration_seconds,
                'Unit': 'Seconds',
                'Dimensions': [
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': metrics.discovery_run_id
                    }
                ]
            })
        
        # Add final counts
        metric_data.extend([
            {
                'MetricName': 'FinalInstanceCount',
                'Value': metrics.instances_discovered,
                'Unit': 'Count'
            },
            {
                'MetricName': 'FinalApplicationCount',
                'Value': metrics.applications_discovered,
                'Unit': 'Count'
            },
            {
                'MetricName': 'FinalAssignmentCount',
                'Value': metrics.assignments_discovered,
                'Unit': 'Count'
            },
            {
                'MetricName': 'FinalErrorCount',
                'Value': metrics.errors_encountered,
                'Unit': 'Count'
            }
        ])
        
        self._put_metric_data(metric_data)
    
    def publish_phase_metrics(self, phase: str, discovery_run_id: str, 
                            count: int, metric_name: str) -> None:
        """Publish phase-specific metrics"""
        self._put_metric_data([
            {
                'MetricName': f'{phase}Completed',
                'Value': 1,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': discovery_run_id
                    }
                ]
            },
            {
                'MetricName': metric_name,
                'Value': count,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': discovery_run_id
                    }
                ]
            }
        ])
    
    def publish_error_metrics(self, error_type: str, discovery_run_id: str, 
                            error_details: Optional[str] = None) -> None:
        """Publish error metrics"""
        metric_data = [
            {
                'MetricName': 'DiscoveryError',
                'Value': 1,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'ErrorType',
                        'Value': error_type
                    },
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': discovery_run_id
                    }
                ]
            }
        ]
        
        self._put_metric_data(metric_data)
    
    def get_discovery_metrics(self, discovery_run_id: str, 
                            hours_back: int = 24) -> Dict[str, Any]:
        """Retrieve discovery metrics for a specific run"""
        end_time = datetime.now(timezone.utc)
        start_time = end_time.replace(hour=end_time.hour - hours_back)
        
        try:
            response = self.cloudwatch.get_metric_statistics(
                Namespace=self.namespace,
                MetricName='DiscoveryProgress',
                Dimensions=[
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': discovery_run_id
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=300,  # 5 minutes
                Statistics=['Maximum']
            )
            
            return {
                'discovery_run_id': discovery_run_id,
                'progress_data': response.get('Datapoints', []),
                'retrieved_at': datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            print(f"Error retrieving metrics: {str(e)}")
            return {}
    
    def _put_metric_data(self, metric_data: List[Dict[str, Any]]) -> None:
        """Put metric data to CloudWatch"""
        try:
            # CloudWatch allows max 20 metrics per request
            for i in range(0, len(metric_data), 20):
                batch = metric_data[i:i+20]
                self.cloudwatch.put_metric_data(
                    Namespace=self.namespace,
                    MetricData=batch
                )
        except Exception as e:
            print(f"Error publishing metrics: {str(e)}")

class ProgressTracker:
    """Track and estimate discovery progress"""
    
    def __init__(self, discovery_run_id: str):
        self.discovery_run_id = discovery_run_id
        self.start_time = datetime.now(timezone.utc)
        self.phases = {
            'initialization': {'weight': 5, 'completed': False},
            'instance_discovery': {'weight': 20, 'completed': False},
            'application_discovery': {'weight': 35, 'completed': False},
            'assignment_discovery': {'weight': 35, 'completed': False},
            'finalization': {'weight': 5, 'completed': False}
        }
        self.total_weight = sum(phase['weight'] for phase in self.phases.values())
    
    def mark_phase_complete(self, phase: str) -> float:
        """Mark a phase as complete and return current progress percentage"""
        if phase in self.phases:
            self.phases[phase]['completed'] = True
        
        completed_weight = sum(
            phase['weight'] for phase in self.phases.values() 
            if phase['completed']
        )
        
        return (completed_weight / self.total_weight) * 100
    
    def get_estimated_completion_time(self) -> Optional[datetime]:
        """Estimate completion time based on current progress"""
        current_progress = self.get_current_progress()
        if current_progress <= 0:
            return None
        
        elapsed_time = datetime.now(timezone.utc) - self.start_time
        total_estimated_time = elapsed_time / (current_progress / 100)
        
        return self.start_time + total_estimated_time
    
    def get_current_progress(self) -> float:
        """Get current progress percentage"""
        completed_weight = sum(
            phase['weight'] for phase in self.phases.values() 
            if phase['completed']
        )
        
        return (completed_weight / self.total_weight) * 100
    
    def get_progress_summary(self) -> Dict[str, Any]:
        """Get comprehensive progress summary"""
        current_progress = self.get_current_progress()
        estimated_completion = self.get_estimated_completion_time()
        
        return {
            'discovery_run_id': self.discovery_run_id,
            'start_time': self.start_time.isoformat(),
            'current_progress': current_progress,
            'estimated_completion': estimated_completion.isoformat() if estimated_completion else None,
            'phases': self.phases,
            'elapsed_time_seconds': (datetime.now(timezone.utc) - self.start_time).total_seconds()
        }

def create_cloudwatch_dashboard(dashboard_name: str = 'IAMIdentityCenterDiscovery') -> Dict[str, Any]:
    """Create CloudWatch dashboard configuration for discovery monitoring"""
    
    dashboard_body = {
        "widgets": [
            {
                "type": "metric",
                "x": 0,
                "y": 0,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        ["IAMIdentityCenter/Discovery", "DiscoveryProgress"],
                        [".", "DiscoveryStarted"],
                        [".", "DiscoveryCompleted"]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": "us-east-1",
                    "title": "Discovery Progress Overview",
                    "period": 300
                }
            },
            {
                "type": "metric",
                "x": 12,
                "y": 0,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        ["IAMIdentityCenter/Discovery", "FinalInstanceCount"],
                        [".", "FinalApplicationCount"],
                        [".", "FinalAssignmentCount"]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": "us-east-1",
                    "title": "Discovery Results",
                    "period": 300
                }
            },
            {
                "type": "metric",
                "x": 0,
                "y": 6,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        ["IAMIdentityCenter/Discovery", "DiscoveryDuration"],
                        [".", "ErrorsEncountered"]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": "us-east-1",
                    "title": "Performance and Errors",
                    "period": 300
                }
            },
            {
                "type": "log",
                "x": 12,
                "y": 6,
                "width": 12,
                "height": 6,
                "properties": {
                    "query": "SOURCE '/aws/lambda/organization-scanner'\n| SOURCE '/aws/lambda/account-scanner'\n| SOURCE '/aws/lambda/application-discovery'\n| SOURCE '/aws/lambda/assignment-discovery'\n| fields @timestamp, @message\n| filter @message like /ERROR/\n| sort @timestamp desc\n| limit 20",
                    "region": "us-east-1",
                    "title": "Recent Errors",
                    "view": "table"
                }
            }
        ]
    }
    
    return {
        'DashboardName': dashboard_name,
        'DashboardBody': json.dumps(dashboard_body)
    }