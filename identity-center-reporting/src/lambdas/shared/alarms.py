"""
CloudWatch alarms configuration for IAM Identity Center Discovery
"""
import boto3
from typing import List, Dict, Any, Optional

class DiscoveryAlarmManager:
    """Manage CloudWatch alarms for discovery operations"""
    
    def __init__(self, region_name: str = 'us-east-1', sns_topic_arn: Optional[str] = None):
        self.cloudwatch = boto3.client('cloudwatch', region_name=region_name)
        self.sns_topic_arn = sns_topic_arn
        self.namespace = 'IAMIdentityCenter/Discovery'
    
    def create_discovery_alarms(self) -> List[str]:
        """Create all discovery-related alarms"""
        alarm_names = []
        
        # High error rate alarm
        alarm_names.append(self._create_error_rate_alarm())
        
        # Discovery duration alarm
        alarm_names.append(self._create_duration_alarm())
        
        # Discovery failure alarm
        alarm_names.append(self._create_failure_alarm())
        
        # Stalled discovery alarm
        alarm_names.append(self._create_stalled_discovery_alarm())
        
        return alarm_names
    
    def _create_error_rate_alarm(self) -> str:
        """Create alarm for high error rate during discovery"""
        alarm_name = 'IAMIdentityCenter-HighErrorRate'
        
        self.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            ComparisonOperator='GreaterThanThreshold',
            EvaluationPeriods=2,
            MetricName='ErrorsEncountered',
            Namespace=self.namespace,
            Period=300,
            Statistic='Sum',
            Threshold=10.0,
            ActionsEnabled=True,
            AlarmActions=[self.sns_topic_arn] if self.sns_topic_arn else [],
            AlarmDescription='High error rate detected during IAM Identity Center discovery',
            Unit='Count',
            TreatMissingData='notBreaching'
        )
        
        return alarm_name
    
    def _create_duration_alarm(self) -> str:
        """Create alarm for discovery taking too long"""
        alarm_name = 'IAMIdentityCenter-LongDiscoveryDuration'
        
        self.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            ComparisonOperator='GreaterThanThreshold',
            EvaluationPeriods=1,
            MetricName='DiscoveryDuration',
            Namespace=self.namespace,
            Period=300,
            Statistic='Maximum',
            Threshold=3600.0,  # 1 hour
            ActionsEnabled=True,
            AlarmActions=[self.sns_topic_arn] if self.sns_topic_arn else [],
            AlarmDescription='Discovery duration exceeded expected threshold (1 hour)',
            Unit='Seconds',
            TreatMissingData='notBreaching'
        )
        
        return alarm_name
    
    def _create_failure_alarm(self) -> str:
        """Create alarm for discovery failures"""
        alarm_name = 'IAMIdentityCenter-DiscoveryFailure'
        
        # This alarm triggers when no DiscoveryCompleted metric is received
        # within expected timeframe after DiscoveryStarted
        self.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            ComparisonOperator='LessThanThreshold',
            EvaluationPeriods=3,
            MetricName='DiscoveryCompleted',
            Namespace=self.namespace,
            Period=1200,  # 20 minutes
            Statistic='Sum',
            Threshold=1.0,
            ActionsEnabled=True,
            AlarmActions=[self.sns_topic_arn] if self.sns_topic_arn else [],
            AlarmDescription='Discovery process appears to have failed - no completion signal received',
            Unit='Count',
            TreatMissingData='breaching'
        )
        
        return alarm_name
    
    def _create_stalled_discovery_alarm(self) -> str:
        """Create alarm for stalled discovery (no progress updates)"""
        alarm_name = 'IAMIdentityCenter-StalledDiscovery'
        
        self.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            ComparisonOperator='LessThanThreshold',
            EvaluationPeriods=4,
            MetricName='DiscoveryProgress',
            Namespace=self.namespace,
            Period=600,  # 10 minutes
            Statistic='Maximum',
            Threshold=1.0,
            ActionsEnabled=True,
            AlarmActions=[self.sns_topic_arn] if self.sns_topic_arn else [],
            AlarmDescription='Discovery appears stalled - no progress updates received',
            Unit='Percent',
            TreatMissingData='breaching'
        )
        
        return alarm_name
    
    def create_lambda_alarms(self, function_names: List[str]) -> List[str]:
        """Create alarms for Lambda function errors and duration"""
        alarm_names = []
        
        for function_name in function_names:
            # Error rate alarm
            error_alarm_name = f'{function_name}-ErrorRate'
            self.cloudwatch.put_metric_alarm(
                AlarmName=error_alarm_name,
                ComparisonOperator='GreaterThanThreshold',
                EvaluationPeriods=2,
                MetricName='Errors',
                Namespace='AWS/Lambda',
                Period=300,
                Statistic='Sum',
                Threshold=5.0,
                ActionsEnabled=True,
                AlarmActions=[self.sns_topic_arn] if self.sns_topic_arn else [],
                AlarmDescription=f'High error rate for Lambda function {function_name}',
                Dimensions=[
                    {
                        'Name': 'FunctionName',
                        'Value': function_name
                    }
                ],
                Unit='Count',
                TreatMissingData='notBreaching'
            )
            alarm_names.append(error_alarm_name)
            
            # Duration alarm
            duration_alarm_name = f'{function_name}-Duration'
            self.cloudwatch.put_metric_alarm(
                AlarmName=duration_alarm_name,
                ComparisonOperator='GreaterThanThreshold',
                EvaluationPeriods=2,
                MetricName='Duration',
                Namespace='AWS/Lambda',
                Period=300,
                Statistic='Average',
                Threshold=600000.0,  # 10 minutes in milliseconds
                ActionsEnabled=True,
                AlarmActions=[self.sns_topic_arn] if self.sns_topic_arn else [],
                AlarmDescription=f'High duration for Lambda function {function_name}',
                Dimensions=[
                    {
                        'Name': 'FunctionName',
                        'Value': function_name
                    }
                ],
                Unit='Milliseconds',
                TreatMissingData='notBreaching'
            )
            alarm_names.append(duration_alarm_name)
        
        return alarm_names
    
    def create_step_function_alarms(self, state_machine_arn: str) -> List[str]:
        """Create alarms for Step Functions execution"""
        alarm_names = []
        
        # Execution failed alarm
        failed_alarm_name = 'IAMIdentityCenter-StepFunctionFailed'
        self.cloudwatch.put_metric_alarm(
            AlarmName=failed_alarm_name,
            ComparisonOperator='GreaterThanThreshold',
            EvaluationPeriods=1,
            MetricName='ExecutionsFailed',
            Namespace='AWS/States',
            Period=300,
            Statistic='Sum',
            Threshold=0.0,
            ActionsEnabled=True,
            AlarmActions=[self.sns_topic_arn] if self.sns_topic_arn else [],
            AlarmDescription='Step Function execution failed',
            Dimensions=[
                {
                    'Name': 'StateMachineArn',
                    'Value': state_machine_arn
                }
            ],
            Unit='Count',
            TreatMissingData='notBreaching'
        )
        alarm_names.append(failed_alarm_name)
        
        # Execution timeout alarm
        timeout_alarm_name = 'IAMIdentityCenter-StepFunctionTimeout'
        self.cloudwatch.put_metric_alarm(
            AlarmName=timeout_alarm_name,
            ComparisonOperator='GreaterThanThreshold',
            EvaluationPeriods=1,
            MetricName='ExecutionsTimedOut',
            Namespace='AWS/States',
            Period=300,
            Statistic='Sum',
            Threshold=0.0,
            ActionsEnabled=True,
            AlarmActions=[self.sns_topic_arn] if self.sns_topic_arn else [],
            AlarmDescription='Step Function execution timed out',
            Dimensions=[
                {
                    'Name': 'StateMachineArn',
                    'Value': state_machine_arn
                }
            ],
            Unit='Count',
            TreatMissingData='notBreaching'
        )
        alarm_names.append(timeout_alarm_name)
        
        return alarm_names
    
    def delete_alarm(self, alarm_name: str) -> None:
        """Delete a specific alarm"""
        try:
            self.cloudwatch.delete_alarms(AlarmNames=[alarm_name])
        except Exception as e:
            print(f"Error deleting alarm {alarm_name}: {str(e)}")
    
    def delete_all_discovery_alarms(self) -> None:
        """Delete all discovery-related alarms"""
        try:
            # Get all alarms with IAMIdentityCenter prefix
            response = self.cloudwatch.describe_alarms(
                AlarmNamePrefix='IAMIdentityCenter-'
            )
            
            alarm_names = [alarm['AlarmName'] for alarm in response['MetricAlarms']]
            
            if alarm_names:
                self.cloudwatch.delete_alarms(AlarmNames=alarm_names)
                print(f"Deleted {len(alarm_names)} alarms")
            else:
                print("No alarms found to delete")
                
        except Exception as e:
            print(f"Error deleting alarms: {str(e)}")

def get_alarm_configurations() -> Dict[str, Any]:
    """Get standard alarm configurations for discovery system"""
    return {
        'discovery_alarms': [
            {
                'name': 'IAMIdentityCenter-HighErrorRate',
                'metric': 'ErrorsEncountered',
                'threshold': 10,
                'comparison': 'GreaterThanThreshold',
                'description': 'High error rate during discovery'
            },
            {
                'name': 'IAMIdentityCenter-LongDiscoveryDuration',
                'metric': 'DiscoveryDuration',
                'threshold': 3600,
                'comparison': 'GreaterThanThreshold',
                'description': 'Discovery taking longer than expected'
            },
            {
                'name': 'IAMIdentityCenter-DiscoveryFailure',
                'metric': 'DiscoveryCompleted',
                'threshold': 1,
                'comparison': 'LessThanThreshold',
                'description': 'Discovery process failed'
            }
        ],
        'lambda_alarms': [
            {
                'metric': 'Errors',
                'threshold': 5,
                'comparison': 'GreaterThanThreshold',
                'description': 'Lambda function error rate'
            },
            {
                'metric': 'Duration',
                'threshold': 600000,
                'comparison': 'GreaterThanThreshold',
                'description': 'Lambda function duration'
            }
        ]
    }