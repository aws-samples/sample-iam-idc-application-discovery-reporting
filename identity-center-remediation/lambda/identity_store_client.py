"""
Identity Store API client wrapper.

This module provides a wrapper around boto3 Identity Store client for interacting
with AWS Identity Center Identity Store APIs to resolve group and user names.
"""

import boto3
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError


class IdentityStoreClientError(Exception):
    """Raised when Identity Store API operations fail."""
    pass


class IdentityStoreClient:
    """Wrapper for AWS Identity Store API operations."""
    
    def __init__(self, region_name: Optional[str] = None):
        """
        Initialize Identity Store client.
        
        Args:
            region_name: AWS region name (defaults to environment/config)
        """
        self.client = boto3.client('identitystore', region_name=region_name)
    
    def describe_group(self, identity_store_id: str, group_id: str) -> Dict[str, Any]:
        """
        Describe a group in Identity Store.
        
        Args:
            identity_store_id: Identity Store ID (directory ID)
            group_id: ID of the group
            
        Returns:
            Dictionary containing group details including:
            - GroupId: Group ID
            - DisplayName: Group display name
            - Description: Group description
            
        Raises:
            IdentityStoreClientError: If API call fails
        """
        try:
            response = self.client.describe_group(
                IdentityStoreId=identity_store_id,
                GroupId=group_id
            )
            return response
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            raise IdentityStoreClientError(
                f"Failed to describe group {group_id}: "
                f"{error_code} - {error_message}"
            ) from e
        except Exception as e:
            raise IdentityStoreClientError(
                f"Unexpected error describing group {group_id}: {e}"
            ) from e
    
    def describe_user(self, identity_store_id: str, user_id: str) -> Dict[str, Any]:
        """
        Describe a user in Identity Store.
        
        Args:
            identity_store_id: Identity Store ID (directory ID)
            user_id: ID of the user
            
        Returns:
            Dictionary containing user details including:
            - UserId: User ID
            - UserName: User name
            - DisplayName: User display name
            
        Raises:
            IdentityStoreClientError: If API call fails
        """
        try:
            response = self.client.describe_user(
                IdentityStoreId=identity_store_id,
                UserId=user_id
            )
            return response
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            raise IdentityStoreClientError(
                f"Failed to describe user {user_id}: "
                f"{error_code} - {error_message}"
            ) from e
        except Exception as e:
            raise IdentityStoreClientError(
                f"Unexpected error describing user {user_id}: {e}"
            ) from e
