"""
Deletion logic for non-compliant Identity Center application assignments.

This module handles the deletion of application assignments and tracks
the deletion status.
"""

from typing import Dict, Any, Optional
from identity_center_client import IdentityCenterClient, IdentityCenterClientError
from retry import retry_with_backoff


class DeletionResult:
    """Result of a deletion operation."""
    
    def __init__(
        self,
        success: bool,
        application_arn: str,
        principal_id: str,
        principal_type: str,
        error_message: Optional[str] = None,
        error_code: Optional[str] = None
    ):
        """
        Initialize deletion result.
        
        Args:
            success: Whether deletion was successful
            application_arn: ARN of the application
            principal_id: ID of the principal
            principal_type: Type of principal (USER or GROUP)
            error_message: Error message if deletion failed
            error_code: Error code if deletion failed
        """
        self.success = success
        self.application_arn = application_arn
        self.principal_id = principal_id
        self.principal_type = principal_type
        self.error_message = error_message
        self.error_code = error_code
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        result = {
            'success': self.success,
            'application_arn': self.application_arn,
            'principal_id': self.principal_id,
            'principal_type': self.principal_type
        }
        if self.error_message:
            result['error_message'] = self.error_message
        if self.error_code:
            result['error_code'] = self.error_code
        return result


def delete_application_assignment(
    application_arn: str,
    principal_id: str,
    principal_type: str,
    client: Optional[IdentityCenterClient] = None
) -> DeletionResult:
    """
    Delete an Identity Center application assignment.
    
    This function attempts to delete an application assignment and returns
    a structured result indicating success or failure. It handles various
    error conditions including permission errors and resource not found errors.
    
    Args:
        application_arn: ARN of the application
        principal_id: ID of the principal (user or group)
        principal_type: Type of principal ('USER' or 'GROUP')
        client: Optional Identity Center client (creates new one if not provided)
        
    Returns:
        DeletionResult with success status and error details if applicable
    """
    # Create client if not provided
    if client is None:
        client = IdentityCenterClient()
    
    try:
        # Attempt deletion with retry logic for transient errors
        @retry_with_backoff(max_attempts=3, base_delay=1.0)
        def _delete_with_retry():
            return client.delete_application_assignment(
                application_arn=application_arn,
                principal_id=principal_id,
                principal_type=principal_type
            )
        
        # Execute deletion
        response = _delete_with_retry()
        
        # Verify deletion was successful
        # AWS API returns empty response on success
        return DeletionResult(
            success=True,
            application_arn=application_arn,
            principal_id=principal_id,
            principal_type=principal_type
        )
        
    except IdentityCenterClientError as e:
        # Extract error details from the exception
        error_message = str(e)
        error_code = None
        
        # Try to extract error code from message
        if 'AccessDeniedException' in error_message or 'AccessDenied' in error_message:
            error_code = 'AccessDeniedException'
        elif 'ResourceNotFoundException' in error_message or 'NotFound' in error_message:
            error_code = 'ResourceNotFoundException'
        elif 'ThrottlingException' in error_message:
            error_code = 'ThrottlingException'
        else:
            error_code = 'UnknownError'
        
        return DeletionResult(
            success=False,
            application_arn=application_arn,
            principal_id=principal_id,
            principal_type=principal_type,
            error_message=error_message,
            error_code=error_code
        )
    
    except Exception as e:
        # Handle unexpected errors
        return DeletionResult(
            success=False,
            application_arn=application_arn,
            principal_id=principal_id,
            principal_type=principal_type,
            error_message=f"Unexpected error during deletion: {str(e)}",
            error_code='UnexpectedError'
        )

