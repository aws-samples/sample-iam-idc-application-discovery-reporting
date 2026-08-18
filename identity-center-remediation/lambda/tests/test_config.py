"""
Unit tests for configuration management module.

Feature: identity-center-app-monitor
"""

import pytest
import os
from config import Config, load_config, parse_boolean, ConfigurationError


class TestParseBoolean:
    """Tests for boolean parsing function."""
    
    def test_parse_true_values(self):
        """Test that various true representations are parsed correctly."""
        assert parse_boolean('true') is True
        assert parse_boolean('True') is True
        assert parse_boolean('TRUE') is True
        assert parse_boolean('1') is True
        assert parse_boolean('yes') is True
        assert parse_boolean('Yes') is True
        assert parse_boolean('YES') is True
    
    def test_parse_false_values(self):
        """Test that various false representations are parsed correctly."""
        assert parse_boolean('false') is False
        assert parse_boolean('False') is False
        assert parse_boolean('FALSE') is False
        assert parse_boolean('0') is False
        assert parse_boolean('no') is False
        assert parse_boolean('No') is False
        assert parse_boolean('NO') is False
    
    def test_parse_none_uses_default(self):
        """Test that None value uses the default."""
        assert parse_boolean(None, default=False) is False
        assert parse_boolean(None, default=True) is True
    
    def test_parse_empty_string_uses_default(self):
        """Test that empty string uses the default."""
        assert parse_boolean('', default=False) is False
        assert parse_boolean('', default=True) is True
    
    def test_parse_invalid_value_uses_default(self):
        """Test that invalid values are handled gracefully with default."""
        assert parse_boolean('invalid', default=False) is False
        assert parse_boolean('invalid', default=True) is True
        assert parse_boolean('maybe', default=False) is False
        assert parse_boolean('2', default=True) is True
    
    def test_parse_whitespace_handling(self):
        """Test that whitespace is handled correctly."""
        assert parse_boolean('  true  ') is True
        assert parse_boolean('  false  ') is False
        assert parse_boolean('   ', default=False) is False


class TestConfig:
    """Tests for Config class."""
    
    def test_config_initialization(self):
        """Test that Config can be initialized with values."""
        config = Config(
            enable_auto_deletion=True,
            sns_topic_arn='arn:aws:sns:us-east-1:123456789012:my-topic'
        )
        
        assert config.enable_auto_deletion is True
        assert config.sns_topic_arn == 'arn:aws:sns:us-east-1:123456789012:my-topic'
    
    def test_config_repr(self):
        """Test that Config has a useful string representation."""
        config = Config(
            enable_auto_deletion=False,
            sns_topic_arn='arn:aws:sns:us-east-1:123456789012:my-topic'
        )
        
        repr_str = repr(config)
        assert 'Config' in repr_str
        assert 'enable_auto_deletion=False' in repr_str
        assert 'arn:aws:sns' in repr_str


class TestLoadConfig:
    """Tests for load_config function."""
    
    def test_missing_enable_auto_deletion_defaults_to_false(self, monkeypatch):
        """
        Test that missing ENABLE_AUTO_DELETION environment variable defaults to false.
        
        Validates: Requirements 3.4
        """
        # Set up environment with only SNS_TOPIC_ARN
        monkeypatch.delenv('ENABLE_AUTO_DELETION', raising=False)
        monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:my-topic')
        
        config = load_config()
        
        assert config.enable_auto_deletion is False
        assert config.sns_topic_arn == 'arn:aws:sns:us-east-1:123456789012:my-topic'
    
    def test_enable_auto_deletion_true(self, monkeypatch):
        """Test that ENABLE_AUTO_DELETION=true is parsed correctly."""
        monkeypatch.setenv('ENABLE_AUTO_DELETION', 'true')
        monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:my-topic')
        
        config = load_config()
        
        assert config.enable_auto_deletion is True
    
    def test_enable_auto_deletion_false(self, monkeypatch):
        """Test that ENABLE_AUTO_DELETION=false is parsed correctly."""
        monkeypatch.setenv('ENABLE_AUTO_DELETION', 'false')
        monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:my-topic')
        
        config = load_config()
        
        assert config.enable_auto_deletion is False
    
    def test_invalid_enable_auto_deletion_handled_gracefully(self, monkeypatch):
        """
        Test that invalid ENABLE_AUTO_DELETION values are handled gracefully.
        
        Validates: Requirements 3.4
        """
        # Set invalid value
        monkeypatch.setenv('ENABLE_AUTO_DELETION', 'invalid_value')
        monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:my-topic')
        
        # Should not raise exception, should use default (false)
        config = load_config()
        
        assert config.enable_auto_deletion is False
    
    def test_missing_sns_topic_arn_raises_error(self, monkeypatch):
        """Test that missing SNS_TOPIC_ARN raises ConfigurationError."""
        monkeypatch.delenv('SNS_TOPIC_ARN', raising=False)
        monkeypatch.setenv('ENABLE_AUTO_DELETION', 'false')
        
        with pytest.raises(ConfigurationError) as exc_info:
            load_config()
        
        assert 'SNS_TOPIC_ARN' in str(exc_info.value)
        assert 'required' in str(exc_info.value).lower()
    
    def test_empty_sns_topic_arn_raises_error(self, monkeypatch):
        """Test that empty SNS_TOPIC_ARN raises ConfigurationError."""
        monkeypatch.setenv('SNS_TOPIC_ARN', '')
        monkeypatch.setenv('ENABLE_AUTO_DELETION', 'false')
        
        with pytest.raises(ConfigurationError) as exc_info:
            load_config()
        
        assert 'SNS_TOPIC_ARN' in str(exc_info.value)
        assert 'empty' in str(exc_info.value).lower()
    
    def test_whitespace_only_sns_topic_arn_raises_error(self, monkeypatch):
        """Test that whitespace-only SNS_TOPIC_ARN raises ConfigurationError."""
        monkeypatch.setenv('SNS_TOPIC_ARN', '   ')
        monkeypatch.setenv('ENABLE_AUTO_DELETION', 'false')
        
        with pytest.raises(ConfigurationError) as exc_info:
            load_config()
        
        assert 'SNS_TOPIC_ARN' in str(exc_info.value)
    
    def test_invalid_arn_format_raises_error(self, monkeypatch):
        """Test that invalid ARN format raises ConfigurationError."""
        monkeypatch.setenv('SNS_TOPIC_ARN', 'not-an-arn')
        monkeypatch.setenv('ENABLE_AUTO_DELETION', 'false')
        
        with pytest.raises(ConfigurationError) as exc_info:
            load_config()
        
        assert 'ARN' in str(exc_info.value)
        assert 'not-an-arn' in str(exc_info.value)
    
    def test_valid_configuration(self, monkeypatch):
        """Test that valid configuration loads successfully."""
        monkeypatch.setenv('ENABLE_AUTO_DELETION', 'true')
        monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-west-2:987654321098:notifications')
        
        config = load_config()
        
        assert config.enable_auto_deletion is True
        assert config.sns_topic_arn == 'arn:aws:sns:us-west-2:987654321098:notifications'



class TestGroupNameRegex:
    """Tests for GROUP_NAME_REGEX configuration."""
    
    def test_missing_group_name_regex_defaults_to_none(self, monkeypatch):
        """Test that missing GROUP_NAME_REGEX defaults to None."""
        monkeypatch.delenv('GROUP_NAME_REGEX', raising=False)
        monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:my-topic')
        
        config = load_config()
        
        assert config.group_name_regex is None
    
    def test_empty_group_name_regex_defaults_to_none(self, monkeypatch):
        """Test that empty GROUP_NAME_REGEX defaults to None."""
        monkeypatch.setenv('GROUP_NAME_REGEX', '')
        monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:my-topic')
        
        config = load_config()
        
        assert config.group_name_regex is None
    
    def test_whitespace_only_group_name_regex_defaults_to_none(self, monkeypatch):
        """Test that whitespace-only GROUP_NAME_REGEX defaults to None."""
        monkeypatch.setenv('GROUP_NAME_REGEX', '   ')
        monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:my-topic')
        
        config = load_config()
        
        assert config.group_name_regex is None
    
    def test_valid_group_name_regex(self, monkeypatch):
        """Test that valid GROUP_NAME_REGEX is loaded correctly."""
        monkeypatch.setenv('GROUP_NAME_REGEX', r'^([^-]+)')
        monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:my-topic')
        
        config = load_config()
        
        assert config.group_name_regex == r'^([^-]+)'
    
    def test_invalid_group_name_regex_raises_error(self, monkeypatch):
        """Test that invalid GROUP_NAME_REGEX raises ConfigurationError."""
        monkeypatch.setenv('GROUP_NAME_REGEX', r'[invalid(regex')
        monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:my-topic')
        
        with pytest.raises(ConfigurationError) as exc_info:
            load_config()
        
        assert 'GROUP_NAME_REGEX' in str(exc_info.value)
        assert 'regex' in str(exc_info.value).lower()
    
    def test_complex_regex_patterns(self, monkeypatch):
        """Test that complex regex patterns are loaded correctly."""
        patterns = [
            r'^([^-]+)',  # Prefix before first dash
            r'([^-]+)$',  # Suffix after last dash
            r'\[([^\]]+)\]',  # Text between brackets
            r'(?i)(dev|prod|test)',  # Case-insensitive alternatives
            r'^[^-]+-([^-]+)',  # Middle segment
        ]
        
        for pattern in patterns:
            monkeypatch.setenv('GROUP_NAME_REGEX', pattern)
            monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:my-topic')
            
            config = load_config()
            
            assert config.group_name_regex == pattern
    
    def test_config_repr_includes_regex(self, monkeypatch):
        """Test that Config repr includes group_name_regex."""
        monkeypatch.setenv('GROUP_NAME_REGEX', r'^([^-]+)')
        monkeypatch.setenv('SNS_TOPIC_ARN', 'arn:aws:sns:us-east-1:123456789012:my-topic')
        
        config = load_config()
        repr_str = repr(config)
        
        assert 'group_name_regex' in repr_str
        assert '^([^-]+)' in repr_str
