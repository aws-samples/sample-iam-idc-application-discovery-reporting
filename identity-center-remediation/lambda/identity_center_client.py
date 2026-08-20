"""
Identity Center API client wrapper.

This module provides a wrapper around boto3 SSO Admin client for interacting
with AWS Identity Center APIs.
"""

import boto3
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError


class IdentityCenterClientError(Exception):
    """Raised when Identity Center API operations fail."""
    pass


class IdentityCenterClient:
    """Wrapper for AWS Identity Center (SSO Admin) API operations."""
    
    def __init__(self, region_name: Optional[str] = None):
        """
        Initialize Identity Center client.
        
        Args:
            region_name: AWS region name (defaults to environment/config)
        """
        self.client = boto3.client('sso-admin', region_name=region_name)

    def get_identity_store_id(self, instance_arn: str) -> str:
        """
        Resolve the Identity Store (directory) ID for an Identity Center instance.

        CloudTrail events for application-assignment changes do not include the
        directoryId, so fall back to looking it up from the configured instance
        ARN. Prefer DescribeInstance; fall back to ListInstances if needed.

        Args:
            instance_arn: Identity Center instance ARN

        Returns:
            Identity Store ID (e.g. d-xxxxxxxxxx), or '' if it cannot be resolved
        """
        try:
            response = self.client.describe_instance(InstanceArn=instance_arn)
            return response.get('IdentityStoreId', '')
        except Exception:
            try:
                paginator = self.client.get_paginator('list_instances')
                for page in paginator.paginate():
                    for instance in page.get('Instances', []):
                        if instance.get('InstanceArn') == instance_arn:
                            return instance.get('IdentityStoreId', '')
            except Exception:
                pass
            return ''

    def delete_application_assignment(
        self,
        application_arn: str,
        principal_id: str,
        principal_type: str
    ) -> Dict[str, Any]:
        """
        Delete an Identity Center application assignment.
        
        Args:
            application_arn: ARN of the application
            principal_id: ID of the principal (user or group)
            principal_type: Type of principal ('USER' or 'GROUP')
            
        Returns:
            Dictionary containing deletion response
            
        Raises:
            IdentityCenterClientError: If API call fails
        """
        try:
            response = self.client.delete_application_assignment(
                ApplicationArn=application_arn,
                PrincipalId=principal_id,
                PrincipalType=principal_type
            )
            return response
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            raise IdentityCenterClientError(
                f"Failed to delete application assignment for {principal_id}: "
                f"{error_code} - {error_message}"
            ) from e
        except Exception as e:
            raise IdentityCenterClientError(
                f"Unexpected error deleting application assignment: {e}"
            ) from e
    

    def get_application_from_instance_and_profile(
        self,
        instance_arn: str,
        instance_id_from_event: str,
        profile_id: str
    ) -> Optional[Dict[str, str]]:
        """
        Get the application ARN and friendly name that uses a specific profile.
        
        The instanceId in AssociateProfile CloudTrail events is based on the managed
        application ARN, not the Identity Center instance. We can construct the
        application ARN from this instanceId and then look it up to get the friendly name.
        
        Pattern:
        - Event instanceId: ins-EXAMPLE123456789
        - Application ID: apl-EXAMPLE123456789 (same suffix)
        - Real instance ID from instance_arn: ssoins-EXAMPLE1234567890
        
        Args:
            instance_arn: Identity Center instance ARN (e.g., arn:aws:sso::123456789012:instance/ssoins-xxx)
            instance_id_from_event: Instance ID from CloudTrail event (e.g., 'ins-EXAMPLE123456789')
            profile_id: Profile ID (e.g., 'p-EXAMPLE123456789')
            
        Returns:
            Dictionary with ApplicationArn and Name, or None if not found
        """
        import os
        
        try:
            # Get management account ID from environment variable (required)
            management_account_id = os.environ.get('MANAGEMENT_ACCOUNT_ID')
            if not management_account_id:
                raise IdentityCenterClientError(
                    "MANAGEMENT_ACCOUNT_ID environment variable is required but not set"
                )
            
            # Extract real instance ID from ARN (e.g., ssoins-xxx)
            real_instance_id = instance_arn.split('/')[-1] if '/' in instance_arn else None
            if not real_instance_id or not instance_id_from_event.startswith('ins-'):
                return None
            
            # Construct application ARN: ins-{suffix} -> apl-{suffix}
            application_id = f"apl-{instance_id_from_event[4:]}"
            application_arn = f"arn:aws:sso::{management_account_id}:application/{real_instance_id}/{application_id}"
            
            # Find application in list to get friendly name
            applications = self.list_applications_for_instance(instance_arn)
            for app in applications:
                if app.get('ApplicationArn') == application_arn:
                    return {'ApplicationArn': application_arn, 'Name': app.get('Name', 'Unknown')}
            
            # Fallback if not found
            return {'ApplicationArn': application_arn, 'Name': f"Application-{application_id}"}
            
        except IdentityCenterClientError:
            # Re-raise configuration errors
            raise
        except Exception:
            # Fallback on any other error
            management_account_id = os.environ.get('MANAGEMENT_ACCOUNT_ID')
            if management_account_id and instance_id_from_event.startswith('ins-'):
                application_id = f"apl-{instance_id_from_event[4:]}"
                real_instance_id = instance_arn.split('/')[-1] if '/' in instance_arn else instance_id_from_event
                return {
                    'ApplicationArn': f"arn:aws:sso::{management_account_id}:application/{real_instance_id}/{application_id}",
                    'Name': f"Application-{application_id}"
                }
            return None
    
    def list_applications_for_instance(
        self,
        instance_arn: str
    ) -> list:
        """
        List all applications in an Identity Center instance.
        
        Args:
            instance_arn: ARN of the Identity Center instance
            
        Returns:
            List of application dictionaries with ARN and Name
            
        Raises:
            IdentityCenterClientError: If API call fails
        """
        try:
            applications = []
            paginator = self.client.get_paginator('list_applications')
            
            for page in paginator.paginate(InstanceArn=instance_arn):
                for app in page.get('Applications', []):
                    applications.append({
                        'ApplicationArn': app.get('ApplicationArn'),
                        'Name': app.get('Name', 'Unknown')
                    })
            
            return applications
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            raise IdentityCenterClientError(
                f"Failed to list applications: "
                f"{error_code} - {error_message}"
            ) from e
        except Exception as e:
            raise IdentityCenterClientError(
                f"Unexpected error listing applications: {e}"
            ) from e
