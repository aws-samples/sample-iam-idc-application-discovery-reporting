"""
Unit tests for Identity Store client module.
"""

import pytest
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError
from identity_store_client import IdentityStoreClient, IdentityStoreClientError


class TestIdentityStoreClient:
    """Unit tests for Identity Store client operations."""
    
    def test_describe_group_success(self):
        """Test successful group description."""
        mock_client = Mock()
        mock_client.describe_group.return_value = {
            'GroupId': 'test-group-id',
            'DisplayName': 'Test Group',
            'Description': 'Test group description'
        }
        
        with patch('identity_store_client.boto3.client', return_value=mock_client):
            client = IdentityStoreClient()
            result = client.describe_group('d-1234567890', 'test-group-id')
            
            assert result['GroupId'] == 'test-group-id'
            assert result['DisplayName'] == 'Test Group'
            mock_client.describe_group.assert_called_once_with(
                IdentityStoreId='d-1234567890',
                GroupId='test-group-id'
            )
    
    def test_describe_group_not_found(self):
        """Test group not found error handling."""
        mock_client = Mock()
        mock_client.describe_group.side_effect = ClientError(
            {'Error': {'Code': 'ResourceNotFoundException', 'Message': 'Group not found'}},
            'DescribeGroup'
        )
        
        with patch('identity_store_client.boto3.client', return_value=mock_client):
            client = IdentityStoreClient()
            
            with pytest.raises(IdentityStoreClientError) as exc_info:
                client.describe_group('d-1234567890', 'test-group-id')
            
            assert 'ResourceNotFoundException' in str(exc_info.value)
    
    def test_describe_user_success(self):
        """Test successful user description."""
        mock_client = Mock()
        mock_client.describe_user.return_value = {
            'UserId': 'test-user-id',
            'UserName': 'testuser',
            'DisplayName': 'Test User'
        }
        
        with patch('identity_store_client.boto3.client', return_value=mock_client):
            client = IdentityStoreClient()
            result = client.describe_user('d-1234567890', 'test-user-id')
            
            assert result['UserId'] == 'test-user-id'
            assert result['UserName'] == 'testuser'
            assert result['DisplayName'] == 'Test User'
            mock_client.describe_user.assert_called_once_with(
                IdentityStoreId='d-1234567890',
                UserId='test-user-id'
            )
    
    def test_describe_user_access_denied(self):
        """Test user access denied error handling."""
        mock_client = Mock()
        mock_client.describe_user.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': 'Access denied'}},
            'DescribeUser'
        )
        
        with patch('identity_store_client.boto3.client', return_value=mock_client):
            client = IdentityStoreClient()
            
            with pytest.raises(IdentityStoreClientError) as exc_info:
                client.describe_user('d-1234567890', 'test-user-id')
            
            assert 'AccessDeniedException' in str(exc_info.value)
