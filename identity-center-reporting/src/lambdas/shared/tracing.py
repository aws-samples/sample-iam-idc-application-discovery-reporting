# AWS X-Ray Tracing Utilities for IAM Identity Center Discovery Solution

import logging
import functools
import json
from typing import Dict, Any, Optional, Callable
from datetime import datetime, timezone

try:
    from aws_xray_sdk.core import xray_recorder, patch_all
    from aws_xray_sdk.core.models import subsegment
    from aws_xray_sdk.core.exceptions import SegmentNotFoundException
    XRAY_AVAILABLE = True
except ImportError:
    XRAY_AVAILABLE = False

logger = logging.getLogger(__name__)

# Patch AWS SDK calls for automatic tracing
if XRAY_AVAILABLE:
    patch_all()

def init_xray_tracing(service_name: str = "iam-identity-center-discovery"):
    """
    Initialize X-Ray tracing for the service
    
    Args:
        service_name: Name of the service for X-Ray segments
    """
    if not XRAY_AVAILABLE:
        logger.warning("AWS X-Ray SDK not available - tracing disabled")
        return
    
    try:
        xray_recorder.configure(
            service=service_name,
            dynamic_naming='*',
            plugins=('EC2Plugin', 'ECSPlugin'),
            daemon_address='127.0.0.1:2000'
        )
        logger.info(f"X-Ray tracing initialized for service: {service_name}")
    except Exception as e:
        logger.warning(f"Failed to initialize X-Ray tracing: {str(e)}")

def trace_lambda_handler(func: Callable) -> Callable:
    """
    Decorator to add X-Ray tracing to Lambda handler functions
    
    Args:
        func: Lambda handler function to trace
    
    Returns:
        Wrapped function with X-Ray tracing
    """
    if not XRAY_AVAILABLE:
        return func
    
    @functools.wraps(func)
    def wrapper(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        try:
            # Add metadata to the main segment
            xray_recorder.put_metadata('lambda_event', {
                'function_name': context.function_name if context else 'unknown',
                'function_version': context.function_version if context else 'unknown',
                'request_id': context.aws_request_id if context else 'unknown',
                'event_keys': list(event.keys()) if event else []
            })
            
            # Add annotations for filtering
            xray_recorder.put_annotation('function_name', context.function_name if context else 'unknown')
            xray_recorder.put_annotation('discovery_run_id', event.get('discovery_run_id', 'unknown'))
            
            # Execute the original function
            result = func(event, context)
            
            # Add result metadata
            if isinstance(result, dict) and 'body' in result:
                try:
                    body = json.loads(result['body']) if isinstance(result['body'], str) else result['body']
                    xray_recorder.put_annotation('success', body.get('success', False))
                    xray_recorder.put_annotation('error_count', len(body.get('errors', [])))
                    
                    if 'count' in body:
                        xray_recorder.put_annotation('items_processed', body['count'])
                except Exception:
                    pass
            
            return result
            
        except Exception as e:
            # Add error information to trace
            xray_recorder.put_annotation('error', True)
            xray_recorder.put_metadata('error_details', _traceable_error(e))
            raise
    
    return wrapper

def trace_discovery_operation(operation_name: str, metadata: Optional[Dict[str, Any]] = None):
    """
    Decorator to trace discovery operations with custom segments
    
    Args:
        operation_name: Name of the discovery operation
        metadata: Optional metadata to add to the segment
    
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        if not XRAY_AVAILABLE:
            return func
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                with xray_recorder.in_subsegment(operation_name) as subseg:
                    # Add operation metadata
                    if metadata:
                        subseg.put_metadata('operation_metadata', metadata)
                    
                    # Add function arguments as metadata (excluding sensitive data)
                    safe_args = _sanitize_args_for_tracing(args, kwargs)
                    subseg.put_metadata('function_args', safe_args)
                    
                    # Add timing annotation
                    start_time = datetime.now(timezone.utc)
                    subseg.put_annotation('start_time', start_time.isoformat())
                    
                    # Execute the function
                    result = func(*args, **kwargs)
                    
                    # Add result metadata
                    end_time = datetime.now(timezone.utc)
                    duration = (end_time - start_time).total_seconds()
                    
                    subseg.put_annotation('duration_seconds', duration)
                    subseg.put_annotation('success', True)
                    
                    # Add result summary
                    if hasattr(result, 'success'):
                        subseg.put_annotation('operation_success', result.success)
                        subseg.put_annotation('items_found', len(result.data) if hasattr(result, 'data') else 0)
                        subseg.put_annotation('error_count', len(result.errors) if hasattr(result, 'errors') else 0)
                    
                    return result
                    
            except Exception as e:
                # Add error information to subsegment
                try:
                    with xray_recorder.current_subsegment() as subseg:
                        subseg.put_annotation('success', False)
                        subseg.put_annotation('error', True)
                        subseg.put_metadata('error_details', _traceable_error(e))
                except (SegmentNotFoundException, AttributeError):
                    pass
                raise
        
        return wrapper
    return decorator

def trace_aws_api_call(service_name: str, operation_name: str, metadata: Optional[Dict[str, Any]] = None):
    """
    Decorator to trace AWS API calls with performance metrics
    
    Args:
        service_name: AWS service name (e.g., 'sso-admin', 'organizations')
        operation_name: API operation name (e.g., 'list_instances')
        metadata: Optional metadata to add to the segment
    
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        if not XRAY_AVAILABLE:
            return func
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            segment_name = f"{service_name}:{operation_name}"
            
            try:
                with xray_recorder.in_subsegment(segment_name) as subseg:
                    # Add AWS service annotations
                    subseg.put_annotation('aws_service', service_name)
                    subseg.put_annotation('aws_operation', operation_name)
                    
                    # Add metadata
                    if metadata:
                        subseg.put_metadata('api_metadata', metadata)
                    
                    # Add request parameters (sanitized)
                    safe_kwargs = _sanitize_args_for_tracing([], kwargs)[1]
                    subseg.put_metadata('request_params', safe_kwargs)
                    
                    # Execute the API call
                    start_time = datetime.now(timezone.utc)
                    result = func(*args, **kwargs)
                    end_time = datetime.now(timezone.utc)
                    
                    # Add performance metrics
                    duration = (end_time - start_time).total_seconds()
                    subseg.put_annotation('api_duration_seconds', duration)
                    subseg.put_annotation('api_success', True)
                    
                    # Add result summary
                    if isinstance(result, dict):
                        if 'ResponseMetadata' in result:
                            http_status = result['ResponseMetadata'].get('HTTPStatusCode')
                            if http_status:
                                subseg.put_annotation('http_status_code', http_status)
                        
                        # Count result items
                        item_count = _count_result_items(result)
                        if item_count > 0:
                            subseg.put_annotation('result_item_count', item_count)
                    
                    return result
                    
            except Exception as e:
                # Add error information
                try:
                    with xray_recorder.current_subsegment() as subseg:
                        subseg.put_annotation('api_success', False)
                        subseg.put_annotation('api_error', True)
                        
                        # Add AWS-specific error details
                        if hasattr(e, 'response'):
                            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                            http_status = e.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
                            
                            subseg.put_annotation('aws_error_code', error_code)
                            if http_status:
                                subseg.put_annotation('http_status_code', http_status)
                            
                            subseg.put_metadata('aws_error_details', _traceable_error(e))
                        else:
                            subseg.put_metadata('error_details', _traceable_error(e))
                except (SegmentNotFoundException, AttributeError):
                    pass
                raise
        
        return wrapper
    return decorator

def add_discovery_metrics(discovery_run_id: str, component: str, metrics: Dict[str, Any]):
    """
    Add discovery-specific metrics to the current X-Ray segment
    
    Args:
        discovery_run_id: Unique identifier for the discovery run
        component: Component name (e.g., 'organization-scanner')
        metrics: Dictionary of metrics to add
    """
    if not XRAY_AVAILABLE:
        return
    
    try:
        xray_recorder.put_annotation('discovery_run_id', discovery_run_id)
        xray_recorder.put_annotation('component', component)
        
        # Add individual metrics as annotations
        for key, value in metrics.items():
            if isinstance(value, (int, float, bool, str)):
                xray_recorder.put_annotation(f"metric_{key}", value)
        
        # Add full metrics as metadata
        xray_recorder.put_metadata('discovery_metrics', {
            'discovery_run_id': discovery_run_id,
            'component': component,
            'metrics': metrics,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.warning(f"Failed to add discovery metrics to X-Ray: {str(e)}")

def trace_performance_bottleneck(operation_name: str, threshold_seconds: float = 5.0):
    """
    Decorator to identify performance bottlenecks by tracing operations that exceed a threshold
    
    Args:
        operation_name: Name of the operation being traced
        threshold_seconds: Threshold in seconds to flag as slow
    
    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        if not XRAY_AVAILABLE:
            return func
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                with xray_recorder.in_subsegment(f"perf_{operation_name}") as subseg:
                    start_time = datetime.now(timezone.utc)
                    
                    result = func(*args, **kwargs)
                    
                    end_time = datetime.now(timezone.utc)
                    duration = (end_time - start_time).total_seconds()
                    
                    # Add performance annotations
                    subseg.put_annotation('operation_name', operation_name)
                    subseg.put_annotation('duration_seconds', duration)
                    subseg.put_annotation('is_slow', duration > threshold_seconds)
                    
                    if duration > threshold_seconds:
                        subseg.put_annotation('performance_bottleneck', True)
                        subseg.put_metadata('bottleneck_details', {
                            'operation': operation_name,
                            'duration': duration,
                            'threshold': threshold_seconds,
                            'slowness_factor': duration / threshold_seconds
                        })
                        logger.warning(f"Performance bottleneck detected: {operation_name} took {duration:.2f}s (threshold: {threshold_seconds}s)")
                    
                    return result
                    
            except Exception as e:
                logger.error(f"Error in performance tracing for {operation_name}: {str(e)}")
                # Continue execution even if tracing fails
                return func(*args, **kwargs)
        
        return wrapper
    return decorator

def _traceable_error(exception: Exception) -> dict:
    """
    Describe an exception for X-Ray without carrying its message.

    A trace is a durable, separately-accessible store, and this module wraps the
    handlers that process Identity Store records. AWS SDK error messages routinely
    quote the resource they failed on -- "User with id <uuid> not found",
    "Application ... for principal ..." -- so writing str(exception) into subsegment
    metadata persists principal identifiers in X-Ray, outside the redaction the log
    statements around it already apply.

    The type and the AWS error code are what a trace is read for: they say which
    operation failed and why, and they are bounded values that cannot carry an
    identifier. The full message stays in CloudWatch, where the handlers log it
    through their own redaction and where IAM controls who can read it.
    """
    details = {'error_type': type(exception).__name__}
    response = getattr(exception, 'response', None)
    if isinstance(response, dict):
        error = response.get('Error', {})
        details['error_code'] = error.get('Code', 'Unknown')
        request_id = response.get('ResponseMetadata', {}).get('RequestId')
        if request_id:
            details['request_id'] = request_id
    return details


def _sanitize_args_for_tracing(args: tuple, kwargs: dict) -> tuple:
    """
    Sanitize function arguments for X-Ray tracing by removing sensitive data
    
    Args:
        args: Positional arguments
        kwargs: Keyword arguments
    
    Returns:
        Tuple of (sanitized_args, sanitized_kwargs)
    """
    # List of sensitive keys to exclude
    sensitive_keys = {
        'password', 'secret', 'token', 'key', 'credential', 'auth',
        'AccessKeyId', 'SecretAccessKey', 'SessionToken'
    }
    
    # Sanitize kwargs
    sanitized_kwargs = {}
    for key, value in kwargs.items():
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            sanitized_kwargs[key] = '[REDACTED]'
        elif isinstance(value, dict):
            sanitized_kwargs[key] = _sanitize_dict(value, sensitive_keys)
        elif isinstance(value, str) and len(value) > 1000:
            sanitized_kwargs[key] = f"[TRUNCATED: {len(value)} chars]"
        else:
            sanitized_kwargs[key] = value
    
    # For args, just include count and types
    sanitized_args = [f"<{type(arg).__name__}>" for arg in args]
    
    return sanitized_args, sanitized_kwargs

def _sanitize_dict(data: dict, sensitive_keys: set) -> dict:
    """
    Recursively sanitize dictionary data for tracing
    
    Args:
        data: Dictionary to sanitize
        sensitive_keys: Set of sensitive key patterns
    
    Returns:
        Sanitized dictionary
    """
    sanitized = {}
    for key, value in data.items():
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            sanitized[key] = '[REDACTED]'
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_dict(value, sensitive_keys)
        elif isinstance(value, list) and len(value) > 100:
            sanitized[key] = f"[LIST: {len(value)} items]"
        elif isinstance(value, str) and len(value) > 500:
            sanitized[key] = f"[STRING: {len(value)} chars]"
        else:
            sanitized[key] = value
    
    return sanitized

def _count_result_items(result: dict) -> int:
    """
    Count items in AWS API result
    
    Args:
        result: AWS API response dictionary
    
    Returns:
        Number of items found in the result
    """
    count = 0
    
    # Common AWS API result patterns
    list_keys = [
        'Instances', 'Applications', 'ApplicationAssignments', 'Accounts',
        'PermissionSets', 'Users', 'Groups', 'Items'
    ]
    
    for key in list_keys:
        if key in result and isinstance(result[key], list):
            count += len(result[key])
    
    return count