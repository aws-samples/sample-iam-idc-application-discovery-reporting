"""
Alerting and notification utilities for IAM Identity Center Discovery Solution
"""

import json
import boto3
import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from enum import Enum

logger = logging.getLogger(__name__)

class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"

class AlertType(Enum):
    """Types of alerts"""
    DISCOVERY_FAILURE = "DISCOVERY_FAILURE"
    ACCESS_DENIED = "ACCESS_DENIED"
    THROTTLING = "THROTTLING"
    DATA_INCONSISTENCY = "DATA_INCONSISTENCY"
    PERFORMANCE_DEGRADATION = "PERFORMANCE_DEGRADATION"
    SYSTEMATIC_FAILURE = "SYSTEMATIC_FAILURE"

class AlertManager:
    """Manages alerting and notifications for the discovery solution"""
    
    def __init__(self):
        self.sns_client = boto3.client('sns')
        self.cloudwatch_client = boto3.client('cloudwatch')
        
        # Get topic ARNs from environment
        self.critical_topic_arn = os.environ.get('CRITICAL_ALERTS_TOPIC_ARN')
        self.warning_topic_arn = os.environ.get('WARNING_ALERTS_TOPIC_ARN')
        self.access_issues_topic_arn = os.environ.get('ACCESS_ISSUES_TOPIC_ARN')
        self.discovery_status_topic_arn = os.environ.get('DISCOVERY_STATUS_TOPIC_ARN')
    
    def send_alert(self, 
                   alert_type: AlertType, 
                   severity: AlertSeverity,
                   message: str,
                   details: Optional[Dict[str, Any]] = None,
                   component: Optional[str] = None) -> bool:
        """
        Send an alert notification
        
        Args:
            alert_type: Type of alert
            severity: Severity level
            message: Alert message
            details: Additional details
            component: Component that generated the alert
            
        Returns:
            bool: True if alert was sent successfully
        """
        try:
            # Determine target topic based on severity and type
            topic_arn = self._get_topic_for_alert(alert_type, severity)
            
            if not topic_arn:
                logger.warning(f"No topic configured for {severity.value} alerts")
                return False
            
            # Create alert payload
            alert_payload = {
                'alert_type': alert_type.value,
                'severity': severity.value,
                'message': message,
                'component': component or 'Unknown',
                'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'details': details or {}
            }
            
            # Create subject line
            subject = f"{severity.value}: {alert_type.value}"
            if component:
                subject += f" - {component}"
            
            # Send notification
            response = self.sns_client.publish(
                TopicArn=topic_arn,
                Subject=subject,
                Message=json.dumps(alert_payload, indent=2)
            )
            
            logger.info(f"Alert sent successfully: {response['MessageId']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send alert: {str(e)}")
            return False
    
    def send_discovery_status(self, 
                            status: str,
                            discovery_run_id: str,
                            details: Optional[Dict[str, Any]] = None) -> bool:
        """
        Send discovery status notification
        
        Args:
            status: Discovery status (started, completed, failed)
            discovery_run_id: Unique identifier for the discovery run
            details: Additional status details
            
        Returns:
            bool: True if notification was sent successfully
        """
        try:
            if not self.discovery_status_topic_arn:
                logger.warning("Discovery status topic not configured")
                return False
            
            status_payload = {
                'discovery_run_id': discovery_run_id,
                'status': status,
                'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                'details': details or {}
            }
            
            subject = f"IAM Identity Center Discovery: {status.upper()}"
            
            response = self.sns_client.publish(
                TopicArn=self.discovery_status_topic_arn,
                Subject=subject,
                Message=json.dumps(status_payload, indent=2)
            )
            
            logger.info(f"Discovery status sent: {response['MessageId']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send discovery status: {str(e)}")
            return False
    
    def send_access_issue_alert(self, 
                               account_id: str,
                               service: str,
                               error_message: str,
                               error_count: int = 1) -> bool:
        """
        Send alert for access issues (permission denied, etc.)
        
        Args:
            account_id: AWS account ID where access failed
            service: AWS service that failed
            error_message: Error message from AWS API
            error_count: Number of consecutive errors
            
        Returns:
            bool: True if alert was sent successfully
        """
        details = {
            'account_id': account_id,
            'service': service,
            'error_message': error_message,
            'error_count': error_count,
            'recommended_actions': [
                'Verify IAM permissions for cross-account access',
                'Check if the account is still active in the organization',
                'Review IAM Identity Center configuration in the target account',
                'Contact account owner to verify service availability'
            ]
        }
        
        severity = AlertSeverity.CRITICAL if error_count >= 5 else AlertSeverity.WARNING
        
        return self.send_alert(
            alert_type=AlertType.ACCESS_DENIED,
            severity=severity,
            message=f"Access denied to {service} in account {account_id}",
            details=details,
            component="Cross-Account Access"
        )
    
    def send_throttling_alert(self, 
                             service: str,
                             operation: str,
                             throttle_count: int) -> bool:
        """
        Send alert for API throttling
        
        Args:
            service: AWS service being throttled
            operation: Specific API operation
            throttle_count: Number of throttling events
            
        Returns:
            bool: True if alert was sent successfully
        """
        details = {
            'service': service,
            'operation': operation,
            'throttle_count': throttle_count,
            'recommended_actions': [
                'Implement exponential backoff with jitter',
                'Review API call patterns for optimization',
                'Consider requesting service limit increases',
                'Check for concurrent executions causing rate limit issues'
            ]
        }
        
        return self.send_alert(
            alert_type=AlertType.THROTTLING,
            severity=AlertSeverity.WARNING,
            message=f"API throttling detected: {service} {operation}",
            details=details,
            component=f"{service} API"
        )
    
    def send_systematic_failure_alert(self, 
                                    failed_components: List[str],
                                    failure_details: Dict[str, Any]) -> bool:
        """
        Send alert for systematic failures across multiple components
        
        Args:
            failed_components: List of components that failed
            failure_details: Details about each failure
            
        Returns:
            bool: True if alert was sent successfully
        """
        details = {
            'failed_components': failed_components,
            'failure_details': failure_details,
            'impact_assessment': 'Multiple components failing - potential service outage',
            'recommended_actions': [
                'Check AWS service health dashboard',
                'Review recent deployments or configuration changes',
                'Escalate to on-call engineer immediately',
                'Consider rolling back recent changes',
                'Monitor for cascading failures'
            ]
        }
        
        return self.send_alert(
            alert_type=AlertType.SYSTEMATIC_FAILURE,
            severity=AlertSeverity.CRITICAL,
            message=f"Systematic failure detected across {len(failed_components)} components",
            details=details,
            component="System Health"
        )
    
    def publish_custom_metric(self, 
                            metric_name: str,
                            value: float,
                            unit: str = 'Count',
                            dimensions: Optional[Dict[str, str]] = None) -> bool:
        """
        Publish custom CloudWatch metric
        
        Args:
            metric_name: Name of the metric
            value: Metric value
            unit: Metric unit
            dimensions: Metric dimensions
            
        Returns:
            bool: True if metric was published successfully
        """
        try:
            metric_data = {
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit,
                'Timestamp': datetime.now(timezone.utc)
            }
            
            if dimensions:
                metric_data['Dimensions'] = [
                    {'Name': k, 'Value': v} for k, v in dimensions.items()
                ]
            
            # Must match the namespace allowed by the Lambda role's
            # cloudwatch:PutMetricData condition (and the one used by
            # monitoring.py/alarms.py) or publishing fails with AccessDenied.
            self.cloudwatch_client.put_metric_data(
                Namespace='IAMIdentityCenter/Discovery',
                MetricData=[metric_data]
            )
            
            logger.debug(f"Custom metric published: {metric_name} = {value}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to publish metric {metric_name}: {str(e)}")
            return False
    
    def _get_topic_for_alert(self, alert_type: AlertType, severity: AlertSeverity) -> Optional[str]:
        """
        Determine the appropriate SNS topic for an alert
        
        Args:
            alert_type: Type of alert
            severity: Severity level
            
        Returns:
            str: SNS topic ARN or None if no topic configured
        """
        # Route access issues to dedicated topic
        if alert_type == AlertType.ACCESS_DENIED:
            return self.access_issues_topic_arn
        
        # Route by severity
        if severity == AlertSeverity.CRITICAL:
            return self.critical_topic_arn
        elif severity == AlertSeverity.WARNING:
            return self.warning_topic_arn
        else:
            return self.discovery_status_topic_arn

# Global alert manager instance
alert_manager = AlertManager()

def send_discovery_failure_alert(component: str, error: str, discovery_run_id: str):
    """Convenience function for discovery failure alerts"""
    alert_manager.send_alert(
        alert_type=AlertType.DISCOVERY_FAILURE,
        severity=AlertSeverity.CRITICAL,
        message=f"Discovery failed in {component}",
        details={
            'error': error,
            'discovery_run_id': discovery_run_id
        },
        component=component
    )

def send_performance_alert(component: str, metric: str, value: float, threshold: float):
    """Convenience function for performance alerts"""
    alert_manager.send_alert(
        alert_type=AlertType.PERFORMANCE_DEGRADATION,
        severity=AlertSeverity.WARNING,
        message=f"Performance degradation detected in {component}",
        details={
            'metric': metric,
            'value': value,
            'threshold': threshold,
            'deviation': ((value - threshold) / threshold) * 100
        },
        component=component
    )

def track_discovery_metrics(discovery_run_id: str, 
                          component: str,
                          accounts_processed: int = 0,
                          applications_found: int = 0,
                          assignments_found: int = 0,
                          errors_encountered: int = 0):
    """Track discovery metrics for monitoring"""
    dimensions = {
        'DiscoveryRunId': discovery_run_id,
        'Component': component
    }
    
    if accounts_processed > 0:
        alert_manager.publish_custom_metric(
            'AccountsProcessed', accounts_processed, 'Count', dimensions
        )
    
    if applications_found > 0:
        alert_manager.publish_custom_metric(
            'ApplicationsFound', applications_found, 'Count', dimensions
        )
    
    if assignments_found > 0:
        alert_manager.publish_custom_metric(
            'AssignmentsFound', assignments_found, 'Count', dimensions
        )
    
    if errors_encountered > 0:
        alert_manager.publish_custom_metric(
            'ErrorsEncountered', errors_encountered, 'Count', dimensions
        )