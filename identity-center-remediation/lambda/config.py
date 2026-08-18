"""
Configuration management module for Identity Center application monitor.

This module reads and validates configuration from environment variables.
"""

import os
from typing import Optional


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing required values."""
    pass


class Config:
    """Configuration container for Lambda function settings."""
    
    def __init__(self, enable_auto_deletion: bool, sns_topic_arn: str, group_name_regex: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            enable_auto_deletion: Whether to automatically delete non-compliant assignments
            sns_topic_arn: ARN of SNS topic for notifications
            group_name_regex: Optional regex pattern to extract friendly group name
        """
        self.enable_auto_deletion = enable_auto_deletion
        self.sns_topic_arn = sns_topic_arn
        self.group_name_regex = group_name_regex
    
    def __repr__(self) -> str:
        return (
            f"Config(enable_auto_deletion={self.enable_auto_deletion}, "
            f"sns_topic_arn='{self.sns_topic_arn}', "
            f"group_name_regex='{self.group_name_regex}')"
        )


def parse_boolean(value: Optional[str], default: bool = False) -> bool:
    """
    Parse a string value as a boolean.
    
    Accepts common boolean representations:
    - True: 'true', 'True', 'TRUE', '1', 'yes', 'Yes', 'YES'
    - False: 'false', 'False', 'FALSE', '0', 'no', 'No', 'NO', None, ''
    
    Args:
        value: String value to parse
        default: Default value if input is None or empty
        
    Returns:
        Boolean value
    """
    if value is None or value == '':
        return default
    
    # Normalize to lowercase for comparison
    normalized = value.strip().lower()
    
    # True values
    if normalized in ('true', '1', 'yes'):
        return True
    
    # False values
    if normalized in ('false', '0', 'no'):
        return False
    
    # Invalid value - use default and handle gracefully
    return default


def load_config() -> Config:
    """
    Load configuration from environment variables.
    
    Environment variables:
    - ENABLE_AUTO_DELETION: Boolean flag for auto-deletion (default: false)
    - SNS_TOPIC_ARN: ARN of SNS topic for notifications (required)
    - GROUP_NAME_REGEX: Optional regex pattern to extract friendly group name (optional)
    
    Returns:
        Config object with validated settings
        
    Raises:
        ConfigurationError: If required configuration is missing or invalid
    """
    import re
    
    # Read ENABLE_AUTO_DELETION with default value of false
    enable_auto_deletion_str = os.environ.get('ENABLE_AUTO_DELETION')
    enable_auto_deletion = parse_boolean(enable_auto_deletion_str, default=False)
    
    # Read SNS_TOPIC_ARN (required)
    sns_topic_arn = os.environ.get('SNS_TOPIC_ARN')
    
    # Validate SNS topic ARN
    if sns_topic_arn is None:
        raise ConfigurationError(
            "SNS_TOPIC_ARN environment variable is required but not set"
        )
    
    if not sns_topic_arn or not sns_topic_arn.strip():
        raise ConfigurationError(
            "SNS_TOPIC_ARN environment variable is empty"
        )
    
    # Basic ARN format validation
    if not sns_topic_arn.startswith('arn:'):
        raise ConfigurationError(
            f"SNS_TOPIC_ARN must be a valid ARN, got: {sns_topic_arn}"
        )
    
    # Read GROUP_NAME_REGEX (optional)
    group_name_regex = os.environ.get('GROUP_NAME_REGEX', '').strip()
    
    # Validate regex pattern if provided
    if group_name_regex:
        try:
            re.compile(group_name_regex)
        except re.error as e:
            raise ConfigurationError(
                f"GROUP_NAME_REGEX is not a valid regex pattern: {e}"
            )
    else:
        group_name_regex = None
    
    return Config(
        enable_auto_deletion=enable_auto_deletion,
        sns_topic_arn=sns_topic_arn,
        group_name_regex=group_name_regex
    )
