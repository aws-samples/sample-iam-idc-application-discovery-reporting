"""
Remediation logic module for non-compliant assignments.

This module determines whether remediation should be triggered based on
validation results.
"""

from typing import Dict, Any
from validation import ValidationResult


def should_trigger_remediation(validation_result: ValidationResult) -> bool:
    """
    Determine if remediation should be triggered based on validation result.
    
    Args:
        validation_result: Result of validation check
        
    Returns:
        True if remediation should be triggered (non-compliant), False otherwise
    """
    return not validation_result.is_compliant


def get_remediation_action(validation_result: ValidationResult, enable_auto_deletion: bool) -> str:
    """
    Determine the remediation action to take.
    
    Args:
        validation_result: Result of validation check
        enable_auto_deletion: Whether auto-deletion is enabled
        
    Returns:
        Remediation action: 'NONE', 'NOTIFICATION_ONLY', or 'DELETED'
    """
    if validation_result.is_compliant:
        return 'NONE'
    
    if enable_auto_deletion:
        return 'DELETED'
    else:
        return 'NOTIFICATION_ONLY'
