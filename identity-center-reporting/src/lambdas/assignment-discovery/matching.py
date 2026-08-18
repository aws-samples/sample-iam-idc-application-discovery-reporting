"""
Matching logic for SSO Group-Application name matching.

This module provides functionality to evaluate whether SSO group names and
their assigned application names match using symmetric whole-word (token)
matching: a match is found when either side's tokens appear as a contiguous
run of whole tokens within the other side's tokens.
"""

import logging
import re
import boto3
from typing import List, Optional

# Import X-Ray tracing utilities
try:
    from aws_xray_sdk.core import xray_recorder
    from aws_xray_sdk.core.exceptions import SegmentNotFoundException
    XRAY_AVAILABLE = True
except ImportError:
    xray_recorder = None
    SegmentNotFoundException = Exception
    XRAY_AVAILABLE = False

logger = logging.getLogger(__name__)

# CloudWatch client for metrics emission
_cloudwatch_client = None
_metrics_enabled = True  # Can be disabled for testing


def _get_cloudwatch_client():
    """Get or create CloudWatch client (lazy initialization)."""
    global _cloudwatch_client
    if _cloudwatch_client is None:
        import os
        region = os.environ.get('AWS_REGION', 'us-east-1')
        _cloudwatch_client = boto3.client('cloudwatch', region_name=region)
    return _cloudwatch_client


def _emit_matching_metrics(evaluation_result: str, error_occurred: bool = False) -> None:
    """
    Emit CloudWatch metrics for matching evaluations.
    
    Args:
        evaluation_result: The result of the matching evaluation ('Yes', 'No', 'Unknown', or '')
        error_occurred: Whether an error occurred during matching
    """
    # Skip metrics emission if disabled (e.g., during testing)
    if not _metrics_enabled:
        return
    
    try:
        cloudwatch = _get_cloudwatch_client()
        namespace = 'IAMIdentityCenter/Discovery'
        
        metric_data = [
            {
                'MetricName': 'MatchingEvaluations',
                'Value': 1,
                'Unit': 'Count'
            }
        ]
        
        # Emit specific result metrics
        if evaluation_result == 'Yes':
            metric_data.append({
                'MetricName': 'MatchedYes',
                'Value': 1,
                'Unit': 'Count'
            })
        elif evaluation_result == 'No':
            metric_data.append({
                'MetricName': 'MatchedNo',
                'Value': 1,
                'Unit': 'Count'
            })
        elif evaluation_result == 'Unknown':
            metric_data.append({
                'MetricName': 'MatchedUnknown',
                'Value': 1,
                'Unit': 'Count'
            })
        
        # Emit error metric if an error occurred
        if error_occurred:
            metric_data.append({
                'MetricName': 'MatchingErrors',
                'Value': 1,
                'Unit': 'Count'
            })
        
        cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=metric_data
        )
    except Exception as e:
        # Don't let metrics emission failures break the matching logic
        logger.warning(f"Failed to emit matching metrics: {str(e)}")


def _tokenize(value: str) -> List[str]:
    """
    Split a name into lowercase whole-word tokens.

    Splits on '-', '_', and whitespace only (not on camelCase or digit
    boundaries), drops empty parts, and lowercases each token. For example:
      'Engineering-Portal' -> ['engineering', 'portal']
      'CustomerPortal'     -> ['customerportal']
      'AWS_Finance Admins' -> ['aws', 'finance', 'admins']
    """
    parts = re.split(r'[-_\s]+', value)
    return [part.lower() for part in parts if part]


def run_in(needle_tokens: List[str], hay_tokens: List[str]) -> bool:
    """
    True when needle_tokens appear as a contiguous run of whole tokens
    anywhere within hay_tokens (first, last, or interior position).

    A single needle token must equal a complete hay token, never a partial
    or prefix match. Vocabulary-free: no hardcoded role/environment words.
    """
    needle_len = len(needle_tokens)
    if needle_len == 0:
        return False

    hay_len = len(hay_tokens)
    if needle_len > hay_len:
        return False
    for start in range(hay_len - needle_len + 1):
        if hay_tokens[start:start + needle_len] == needle_tokens:
            return True
    return False


def evaluate_group_application_match(
    principal_type: str,
    principal_name: Optional[str],
    application_name: Optional[str]
) -> str:
    """
    Evaluate if a group name and an application name match by symmetric
    whole-word (token) matching.

    This function performs case-insensitive symmetric whole-word (token)
    matching to determine if either the principal_name (group name) tokens
    appear as a contiguous run of whole tokens within the application_name
    tokens, or vice versa.

    Args:
        principal_type: Type of principal ('USER' or 'GROUP')
        principal_name: Name of the principal (group or user)
        application_name: Name of the application

    Returns:
        'Yes' if match found (either side's tokens appear as a contiguous
            whole-word run within the other side's tokens)
        'No' if no match found or edge cases (None, empty, whitespace)
        'Unknown' if an exception occurs during matching
        Empty string ('') for USER principals (no matching performed)
    
    Edge Cases:
        - USER principals: Returns empty string (no matching)
        - None principal_name: Returns 'No'
        - Empty principal_name: Returns 'No'
        - Whitespace-only principal_name: Returns 'No'
        - None application_name: Returns 'No'
        - Empty application_name: Returns 'No'
        - Whitespace-only application_name: Returns 'No'
        - Exceptions during matching: Returns 'Unknown' and logs error
    """
    result = ''
    error_occurred = False
    
    # Create X-Ray subsegment for matching evaluation
    if XRAY_AVAILABLE:
        try:
            subsegment = xray_recorder.begin_subsegment('matching_evaluation')
        except (SegmentNotFoundException, AttributeError):
            subsegment = None
    else:
        subsegment = None
    
    try:
        # Add annotations for filtering and analysis
        if subsegment:
            subsegment.put_annotation('principal_type', principal_type)
            subsegment.put_annotation('has_principal_name', principal_name is not None)
            subsegment.put_annotation('has_application_name', application_name is not None)
        
        # USER principals don't get matching logic applied
        if principal_type == 'USER':
            result = ''
            if subsegment:
                subsegment.put_annotation('matching_result', 'skipped_user')
            return result
        
        # Handle None values
        if principal_name is None or application_name is None:
            result = 'No'
            if subsegment:
                subsegment.put_annotation('matching_result', result)
                subsegment.put_annotation('edge_case', 'none_value')
            _emit_matching_metrics(result, error_occurred)
            return result
        
        # Handle empty strings and whitespace-only strings
        if not principal_name.strip() or not application_name.strip():
            result = 'No'
            if subsegment:
                subsegment.put_annotation('matching_result', result)
                subsegment.put_annotation('edge_case', 'empty_or_whitespace')
            _emit_matching_metrics(result, error_occurred)
            return result
        
        # Perform symmetric whole-word (token) matching
        group_tokens = _tokenize(principal_name)
        app_tokens = _tokenize(application_name)
        if run_in(app_tokens, group_tokens) or run_in(group_tokens, app_tokens):
            result = 'Yes'
        else:
            result = 'No'
        
        # Add matching result annotation
        if subsegment:
            subsegment.put_annotation('matching_result', result)
            subsegment.put_metadata('matching_details', {
                'principal_name': principal_name,
                'application_name': application_name,
                'result': result
            })
        
        _emit_matching_metrics(result, error_occurred)
        return result
    
    except Exception as e:
        error_occurred = True
        result = 'Unknown'
        
        # Add error annotations
        if subsegment:
            subsegment.put_annotation('matching_result', result)
            subsegment.put_annotation('error', True)
            subsegment.put_metadata('error_details', {
                'error_type': type(e).__name__,
                'error_message': str(e)
            })
        
        # Log the error with context
        logger.error(
            f"Matching evaluation failed: "
            f"principal_type='{principal_type}', "
            f"principal_name='{principal_name}', "
            f"application_name='{application_name}', "
            f"error='{str(e)}'"
        )
        
        _emit_matching_metrics(result, error_occurred)
        return result
    
    finally:
        # End the subsegment
        if subsegment and XRAY_AVAILABLE:
            try:
                xray_recorder.end_subsegment()
            except Exception:
                pass
