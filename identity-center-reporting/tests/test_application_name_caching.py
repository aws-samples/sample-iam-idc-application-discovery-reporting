"""
Unit tests for application name caching functionality.

This module tests the get_application_name() function that retrieves
application names from DynamoDB with in-memory caching.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add the src/lambdas directory to the path for shared imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas'))

# Mock the shared/edge_cases modules only for the duration of the import —
# leaving Mock objects in sys.modules poisons every later test module that
# imports the real 'shared' package or a different Lambda's 'index'.
_mocked = ['shared', 'shared.utils', 'shared.models', 'shared.tracing', 'edge_cases', 'index']
_saved = {m: sys.modules.get(m) for m in _mocked}
sys.modules.pop('index', None)
sys.modules['shared'] = Mock()
sys.modules['shared.utils'] = Mock()
sys.modules['shared.models'] = Mock()
sys.modules['shared.tracing'] = Mock()
sys.modules['edge_cases'] = Mock()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'assignment-discovery'))
try:
    import index as assignment_discovery_index
finally:
    for _mod, _orig in _saved.items():
        if _orig is not None:
            sys.modules[_mod] = _orig
        else:
            sys.modules.pop(_mod, None)


TEST_INSTANCE_ARN = "arn:aws:sso:::instance/ssoins-abc"


class TestApplicationNameCaching:
    """Test suite for application name caching functionality."""
    
    def setup_method(self):
        """Clear the cache before each test."""
        assignment_discovery_index._application_name_cache.clear()
    
    @patch.dict(os.environ, {'APPLICATIONS_TABLE': 'test-applications-table'})
    def test_cache_miss_queries_dynamodb(self):
        """
        Test that cache miss queries DynamoDB.
        Validates: Requirements 1.1, 1.2, 1.3
        """
        application_arn = "arn:aws:sso::123456789012:application/ssoins-abc/apl-123"
        expected_name = "Engineering-Portal"
        
        # Mock DynamoDB response
        mock_table = Mock()
        mock_table.get_item.return_value = {
            'Item': {
                'application_arn': application_arn,
                'name': expected_name
            }
        }
        
        with patch.object(assignment_discovery_index.boto3, 'resource') as mock_boto3:
            mock_dynamodb = Mock()
            mock_dynamodb.Table.return_value = mock_table
            mock_boto3.return_value = mock_dynamodb
            
            # Call the function
            result = assignment_discovery_index.get_application_name(application_arn, TEST_INSTANCE_ARN)
            
            # Verify DynamoDB was queried
            assert mock_table.get_item.called
            assert result == expected_name
    
    @patch.dict(os.environ, {'APPLICATIONS_TABLE': 'test-applications-table'})
    def test_cache_hit_returns_cached_value(self):
        """
        Test that cache hit returns cached value without querying DynamoDB.
        Validates: Requirements 1.1, 1.2, 1.3
        """
        application_arn = "arn:aws:sso::123456789012:application/ssoins-abc/apl-123"
        cached_name = "Engineering-Portal"
        
        # Pre-populate the cache
        assignment_discovery_index._application_name_cache[application_arn] = cached_name
        
        # Mock DynamoDB (should not be called)
        mock_table = Mock()
        
        with patch.object(assignment_discovery_index.boto3, 'resource') as mock_boto3:
            mock_dynamodb = Mock()
            mock_dynamodb.Table.return_value = mock_table
            mock_boto3.return_value = mock_dynamodb
            
            # Call the function
            result = assignment_discovery_index.get_application_name(application_arn, TEST_INSTANCE_ARN)
            
            # Verify DynamoDB was NOT queried
            assert not mock_table.get_item.called
            assert result == cached_name
    
    @patch.dict(os.environ, {'APPLICATIONS_TABLE': 'test-applications-table'})
    def test_missing_application_returns_none(self):
        """
        Test that missing application returns None.
        Validates: Requirements 1.1, 1.2, 1.3
        """
        application_arn = "arn:aws:sso::123456789012:application/ssoins-abc/apl-nonexistent"
        
        # Mock DynamoDB response with no Item
        mock_table = Mock()
        mock_table.get_item.return_value = {}  # No 'Item' key
        
        with patch.object(assignment_discovery_index.boto3, 'resource') as mock_boto3:
            mock_dynamodb = Mock()
            mock_dynamodb.Table.return_value = mock_table
            mock_boto3.return_value = mock_dynamodb
            
            # Call the function
            result = assignment_discovery_index.get_application_name(application_arn, TEST_INSTANCE_ARN)
            
            # Verify None is returned
            assert result is None
    
    @patch.dict(os.environ, {'APPLICATIONS_TABLE': 'test-applications-table'})
    def test_cache_persists_across_multiple_calls(self):
        """
        Test that cache persists across multiple calls.
        Validates: Requirements 1.1, 1.2, 1.3
        """
        application_arn = "arn:aws:sso::123456789012:application/ssoins-abc/apl-123"
        expected_name = "Engineering-Portal"
        
        # Mock DynamoDB response
        mock_table = Mock()
        mock_table.get_item.return_value = {
            'Item': {
                'application_arn': application_arn,
                'name': expected_name
            }
        }
        
        with patch.object(assignment_discovery_index.boto3, 'resource') as mock_boto3:
            mock_dynamodb = Mock()
            mock_dynamodb.Table.return_value = mock_table
            mock_boto3.return_value = mock_dynamodb
            
            # First call - should query DynamoDB
            result1 = assignment_discovery_index.get_application_name(application_arn, TEST_INSTANCE_ARN)
            assert result1 == expected_name
            assert mock_table.get_item.call_count == 1
            
            # Second call - should use cache
            result2 = assignment_discovery_index.get_application_name(application_arn, TEST_INSTANCE_ARN)
            assert result2 == expected_name
            assert mock_table.get_item.call_count == 1  # Still 1, not called again
            
            # Third call - should still use cache
            result3 = assignment_discovery_index.get_application_name(application_arn, TEST_INSTANCE_ARN)
            assert result3 == expected_name
            assert mock_table.get_item.call_count == 1  # Still 1, not called again
    
    @patch.dict(os.environ, {'APPLICATIONS_TABLE': 'test-applications-table'})
    def test_different_arns_cached_separately(self):
        """
        Test that different ARNs are cached separately.
        """
        arn1 = "arn:aws:sso::123456789012:application/ssoins-abc/apl-123"
        arn2 = "arn:aws:sso::123456789012:application/ssoins-abc/apl-456"
        name1 = "Engineering-Portal"
        name2 = "Sales-Dashboard"
        
        # Mock DynamoDB responses
        mock_table = Mock()
        
        def get_item_side_effect(**kwargs):
            arn = kwargs['Key']['application_arn']
            if arn == arn1:
                return {'Item': {'application_arn': arn1, 'name': name1}}
            elif arn == arn2:
                return {'Item': {'application_arn': arn2, 'name': name2}}
            return {}
        
        mock_table.get_item.side_effect = get_item_side_effect
        
        with patch.object(assignment_discovery_index.boto3, 'resource') as mock_boto3:
            mock_dynamodb = Mock()
            mock_dynamodb.Table.return_value = mock_table
            mock_boto3.return_value = mock_dynamodb
            
            # Get first application name
            result1 = assignment_discovery_index.get_application_name(arn1, TEST_INSTANCE_ARN)
            assert result1 == name1
            
            # Get second application name
            result2 = assignment_discovery_index.get_application_name(arn2, TEST_INSTANCE_ARN)
            assert result2 == name2
            
            # Verify both are cached
            assert assignment_discovery_index._application_name_cache[arn1] == name1
            assert assignment_discovery_index._application_name_cache[arn2] == name2
            
            # Get them again - should use cache
            result1_cached = assignment_discovery_index.get_application_name(arn1, TEST_INSTANCE_ARN)
            result2_cached = assignment_discovery_index.get_application_name(arn2, TEST_INSTANCE_ARN)
            
            assert result1_cached == name1
            assert result2_cached == name2
            
            # Should have been called exactly twice (once for each ARN)
            assert mock_table.get_item.call_count == 2
    
    @patch.dict(os.environ, {'APPLICATIONS_TABLE': 'test-applications-table'})
    def test_dynamodb_exception_returns_none(self):
        """
        Test that DynamoDB exceptions are handled gracefully.
        """
        application_arn = "arn:aws:sso::123456789012:application/ssoins-abc/apl-123"
        
        # Mock DynamoDB to raise an exception
        mock_table = Mock()
        mock_table.get_item.side_effect = Exception("DynamoDB error")
        
        with patch.object(assignment_discovery_index.boto3, 'resource') as mock_boto3:
            mock_dynamodb = Mock()
            mock_dynamodb.Table.return_value = mock_table
            mock_boto3.return_value = mock_dynamodb
            
            # Call the function
            result = assignment_discovery_index.get_application_name(application_arn, TEST_INSTANCE_ARN)
            
            # Verify None is returned on exception
            assert result is None
    
    @patch.dict(os.environ, {'APPLICATIONS_TABLE': 'test-applications-table'})
    def test_missing_name_field_returns_none(self):
        """
        Test that missing 'name' field in DynamoDB item returns None.
        """
        application_arn = "arn:aws:sso::123456789012:application/ssoins-abc/apl-123"
        
        # Mock DynamoDB response with Item but no 'name' field
        mock_table = Mock()
        mock_table.get_item.return_value = {
            'Item': {
                'application_arn': application_arn
                # 'name' field is missing
            }
        }
        
        with patch.object(assignment_discovery_index.boto3, 'resource') as mock_boto3:
            mock_dynamodb = Mock()
            mock_dynamodb.Table.return_value = mock_table
            mock_boto3.return_value = mock_dynamodb
            
            # Call the function
            result = assignment_discovery_index.get_application_name(application_arn, TEST_INSTANCE_ARN)
            
            # Verify None is returned
            assert result is None
    
    def test_environment_variable_not_set(self):
        """
        Test that missing APPLICATIONS_TABLE environment variable is handled.
        """
        application_arn = "arn:aws:sso::123456789012:application/ssoins-abc/apl-123"
        
        with patch.dict(os.environ, {}, clear=True):
            # Call the function
            result = assignment_discovery_index.get_application_name(application_arn, TEST_INSTANCE_ARN)
            
            # Verify None is returned when env var is missing
            assert result is None
