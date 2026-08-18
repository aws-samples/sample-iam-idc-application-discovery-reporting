"""
Performance metrics collection for IAM Identity Center Discovery
"""
import time
import boto3
import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from contextlib import contextmanager
from dataclasses import dataclass, asdict

@dataclass
class PerformanceMetrics:
    """Performance metrics data class"""
    operation_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None
    items_processed: int = 0
    api_calls_made: int = 0
    memory_used_mb: Optional[float] = None
    discovery_run_id: Optional[str] = None

class PerformanceCollector:
    """Collect and publish performance metrics"""
    
    def __init__(self, discovery_run_id: str, region_name: str = 'us-east-1'):
        self.discovery_run_id = discovery_run_id
        self.cloudwatch = boto3.client('cloudwatch', region_name=region_name)
        self.namespace = 'IAMIdentityCenter/Discovery/Performance'
        self.metrics: List[PerformanceMetrics] = []
    
    @contextmanager
    def measure_operation(self, operation_name: str, items_count: int = 0):
        """Context manager to measure operation performance"""
        start_time = datetime.now(timezone.utc)
        start_memory = self._get_memory_usage()
        api_calls = 0
        error_message = None
        success = True
        
        try:
            yield lambda: setattr(self, '_api_calls', getattr(self, '_api_calls', 0) + 1)
        except Exception as e:
            success = False
            error_message = str(e)
            raise
        finally:
            end_time = datetime.now(timezone.utc)
            duration_ms = (end_time - start_time).total_seconds() * 1000
            end_memory = self._get_memory_usage()
            memory_used = end_memory - start_memory if end_memory and start_memory else None
            
            metrics = PerformanceMetrics(
                operation_name=operation_name,
                start_time=start_time,
                end_time=end_time,
                duration_ms=duration_ms,
                success=success,
                error_message=error_message,
                items_processed=items_count,
                api_calls_made=getattr(self, '_api_calls', 0),
                memory_used_mb=memory_used,
                discovery_run_id=self.discovery_run_id
            )
            
            self.metrics.append(metrics)
            self._publish_performance_metrics(metrics)
    
    def _get_memory_usage(self) -> Optional[float]:
        """Get current memory usage in MB"""
        try:
            import psutil
            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # Convert to MB
        except ImportError:
            return None
    
    def _publish_performance_metrics(self, metrics: PerformanceMetrics) -> None:
        """Publish performance metrics to CloudWatch"""
        metric_data = [
            {
                'MetricName': 'OperationDuration',
                'Value': metrics.duration_ms,
                'Unit': 'Milliseconds',
                'Dimensions': [
                    {
                        'Name': 'Operation',
                        'Value': metrics.operation_name
                    },
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': self.discovery_run_id
                    },
                    {
                        'Name': 'Success',
                        'Value': str(metrics.success)
                    }
                ]
            },
            {
                'MetricName': 'ItemsProcessed',
                'Value': metrics.items_processed,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'Operation',
                        'Value': metrics.operation_name
                    },
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': self.discovery_run_id
                    }
                ]
            },
            {
                'MetricName': 'APICallsPerOperation',
                'Value': metrics.api_calls_made,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'Operation',
                        'Value': metrics.operation_name
                    },
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': self.discovery_run_id
                    }
                ]
            }
        ]
        
        if metrics.memory_used_mb:
            metric_data.append({
                'MetricName': 'MemoryUsed',
                'Value': metrics.memory_used_mb,
                'Unit': 'Megabytes',
                'Dimensions': [
                    {
                        'Name': 'Operation',
                        'Value': metrics.operation_name
                    },
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': self.discovery_run_id
                    }
                ]
            })
        
        if not metrics.success:
            metric_data.append({
                'MetricName': 'OperationErrors',
                'Value': 1,
                'Unit': 'Count',
                'Dimensions': [
                    {
                        'Name': 'Operation',
                        'Value': metrics.operation_name
                    },
                    {
                        'Name': 'DiscoveryRunId',
                        'Value': self.discovery_run_id
                    }
                ]
            })
        
        try:
            self.cloudwatch.put_metric_data(
                Namespace=self.namespace,
                MetricData=metric_data
            )
        except Exception as e:
            print(f"Error publishing performance metrics: {str(e)}")
    
    def get_operation_summary(self) -> Dict[str, Any]:
        """Get summary of all operations performed"""
        if not self.metrics:
            return {}
        
        total_duration = sum(m.duration_ms for m in self.metrics if m.duration_ms)
        total_items = sum(m.items_processed for m in self.metrics)
        total_api_calls = sum(m.api_calls_made for m in self.metrics)
        successful_operations = sum(1 for m in self.metrics if m.success)
        failed_operations = len(self.metrics) - successful_operations
        
        operations_by_type = {}
        for metric in self.metrics:
            if metric.operation_name not in operations_by_type:
                operations_by_type[metric.operation_name] = {
                    'count': 0,
                    'total_duration_ms': 0,
                    'total_items': 0,
                    'total_api_calls': 0,
                    'success_count': 0,
                    'error_count': 0
                }
            
            op_stats = operations_by_type[metric.operation_name]
            op_stats['count'] += 1
            op_stats['total_duration_ms'] += metric.duration_ms or 0
            op_stats['total_items'] += metric.items_processed
            op_stats['total_api_calls'] += metric.api_calls_made
            
            if metric.success:
                op_stats['success_count'] += 1
            else:
                op_stats['error_count'] += 1
        
        return {
            'discovery_run_id': self.discovery_run_id,
            'summary': {
                'total_operations': len(self.metrics),
                'successful_operations': successful_operations,
                'failed_operations': failed_operations,
                'total_duration_ms': total_duration,
                'total_items_processed': total_items,
                'total_api_calls': total_api_calls,
                'average_duration_ms': total_duration / len(self.metrics) if self.metrics else 0
            },
            'operations_by_type': operations_by_type,
            'generated_at': datetime.now(timezone.utc).isoformat()
        }
    
    def export_metrics(self) -> List[Dict[str, Any]]:
        """Export all collected metrics"""
        return [asdict(metric) for metric in self.metrics]

class ThroughputCalculator:
    """Calculate throughput metrics for discovery operations"""
    
    def __init__(self):
        self.operation_times: Dict[str, List[float]] = {}
        self.operation_counts: Dict[str, List[int]] = {}
    
    def record_operation(self, operation_name: str, duration_ms: float, items_count: int) -> None:
        """Record an operation for throughput calculation"""
        if operation_name not in self.operation_times:
            self.operation_times[operation_name] = []
            self.operation_counts[operation_name] = []
        
        self.operation_times[operation_name].append(duration_ms)
        self.operation_counts[operation_name].append(items_count)
    
    def calculate_throughput(self, operation_name: str) -> Dict[str, float]:
        """Calculate throughput metrics for an operation"""
        if operation_name not in self.operation_times:
            return {}
        
        times = self.operation_times[operation_name]
        counts = self.operation_counts[operation_name]
        
        if not times or not counts:
            return {}
        
        total_time_seconds = sum(times) / 1000  # Convert to seconds
        total_items = sum(counts)
        
        if total_time_seconds == 0:
            return {}
        
        return {
            'items_per_second': total_items / total_time_seconds,
            'average_time_per_item_ms': (sum(times) / total_items) if total_items > 0 else 0,
            'total_operations': len(times),
            'total_items_processed': total_items,
            'total_time_seconds': total_time_seconds
        }
    
    def get_all_throughput_metrics(self) -> Dict[str, Dict[str, float]]:
        """Get throughput metrics for all operations"""
        return {
            operation: self.calculate_throughput(operation)
            for operation in self.operation_times.keys()
        }

def create_performance_dashboard() -> Dict[str, Any]:
    """Create CloudWatch dashboard for performance monitoring"""
    
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
                        ["IAMIdentityCenter/Discovery/Performance", "OperationDuration", "Operation", "OrganizationScan"],
                        ["...", "AccountScan"],
                        ["...", "ApplicationDiscovery"],
                        ["...", "AssignmentDiscovery"]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": "us-east-1",
                    "title": "Operation Duration by Type",
                    "period": 300,
                    "stat": "Average"
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
                        ["IAMIdentityCenter/Discovery/Performance", "ItemsProcessed", "Operation", "OrganizationScan"],
                        ["...", "AccountScan"],
                        ["...", "ApplicationDiscovery"],
                        ["...", "AssignmentDiscovery"]
                    ],
                    "view": "timeSeries",
                    "stacked": True,
                    "region": "us-east-1",
                    "title": "Items Processed by Operation",
                    "period": 300,
                    "stat": "Sum"
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
                        ["IAMIdentityCenter/Discovery/Performance", "APICallsPerOperation", "Operation", "OrganizationScan"],
                        ["...", "AccountScan"],
                        ["...", "ApplicationDiscovery"],
                        ["...", "AssignmentDiscovery"]
                    ],
                    "view": "timeSeries",
                    "stacked": True,
                    "region": "us-east-1",
                    "title": "API Calls by Operation",
                    "period": 300,
                    "stat": "Sum"
                }
            },
            {
                "type": "metric",
                "x": 12,
                "y": 6,
                "width": 12,
                "height": 6,
                "properties": {
                    "metrics": [
                        ["IAMIdentityCenter/Discovery/Performance", "MemoryUsed", "Operation", "OrganizationScan"],
                        ["...", "AccountScan"],
                        ["...", "ApplicationDiscovery"],
                        ["...", "AssignmentDiscovery"]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": "us-east-1",
                    "title": "Memory Usage by Operation",
                    "period": 300,
                    "stat": "Average"
                }
            }
        ]
    }
    
    return {
        'DashboardName': 'IAMIdentityCenterDiscovery-Performance',
        'DashboardBody': json.dumps(dashboard_body)
    }