"""
Unit tests for deletion error cases.

Tests permission errors, successful deletion flow, and deletion failure flow.
_Requirements: 5.3, 5.4, 5.5_
"""

import pytest
from unittest.mock import Mock, MagicMock
from botocore.exceptions import ClientError
from deletion import (
    delete_application_assignment,
    DeletionResult
)
from identity_center_client import IdentityCenterClient, IdentityCenterClientError


class TestDeletionErrorCases:
    """Unit tests for deletion error handling."""
    
    def test_permission_error_is_handled_correctly(self):
        """
        Test that permission errors (AccessDeniedException) are handled
        correctly and return a failure result with appropriate error details.
        
        _Requirements: 5.3, 5.5_
        """
        # Create mock client that raises AccessDeniedException
        mock_client = Mock(spec=IdentityCenterClient)
        mock_client.delete_application_assignment = Mock(
            side_effect=IdentityCenterClientError(
                "Failed to delete application assignment: AccessDeniedException - Access denied"
            )
        )
        
        # Attempt deletion
        result = delete_application_assignment(
            application_arn="arn:aws:sso:::123456789012:instance/test/application/test",
            principal_id="12345678-1234-1234-1234-123456789012",
            principal_type="GROUP",
            client=mock_client
        )
        
        # Verify result indicates failure
        assert result.success is False
        assert result.error_message is not None
        assert 'AccessDenied' in result.error_message or 'Access denied' in result.error_message
        assert result.error_code == 'AccessDeniedException'
    
    def test_resource_not_found_error_is_handled(self):
        """
        Test that ResourceNotFoundException is handled correctly.
        This can occur if the assignment was already deleted.
        
        _Requirements: 5.3, 5.4_
        """
        # Create mock client that raises ResourceNotFoundException
        mock_client = Mock(spec=IdentityCenterClient)
        mock_client.delete_application_assignment = Mock(
            side_effect=IdentityCenterClientError(
                "Failed to delete application assignment: ResourceNotFoundException - Resource not found"
            )
        )
        
        # Attempt deletion
        result = delete_application_assignment(
            application_arn="arn:aws:sso:::123456789012:instance/test/application/test",
            principal_id="12345678-1234-1234-1234-123456789012",
            principal_type="GROUP",
            client=mock_client
        )
        
        # Verify result indicates failure with appropriate error
        assert result.success is False
        assert result.error_message is not None
        assert 'NotFound' in result.error_message or 'not found' in result.error_message.lower()
        assert result.error_code == 'ResourceNotFoundException'
    
    def test_successful_deletion_flow(self):
        """
        Test the complete successful deletion flow.
        
        _Requirements: 5.1, 5.2, 5.4_
        """
        # Create mock client that succeeds
        mock_client = Mock(spec=IdentityCenterClient)
        mock_client.delete_application_assignment = Mock(return_value={})
        
        # Perform deletion
        result = delete_application_assignment(
            application_arn="arn:aws:sso:::123456789012:instance/test/application/test",
            principal_id="12345678-1234-1234-1234-123456789012",
            principal_type="GROUP",
            client=mock_client
        )
        
        # Verify deletion was called with correct parameters
        mock_client.delete_application_assignment.assert_called_once_with(
            application_arn="arn:aws:sso:::123456789012:instance/test/application/test",
            principal_id="12345678-1234-1234-1234-123456789012",
            principal_type="GROUP"
        )
        
        # Verify result indicates success
        assert result.success is True
        assert result.error_message is None
        assert result.error_code is None
        assert result.application_arn == "arn:aws:sso:::123456789012:instance/test/application/test"
        assert result.principal_id == "12345678-1234-1234-1234-123456789012"
        assert result.principal_type == "GROUP"
    
    def test_deletion_failure_flow(self):
        """
        Test the complete deletion failure flow with various error types.
        
        _Requirements: 5.3, 5.4, 5.5_
        """
        # Test with generic error
        mock_client = Mock(spec=IdentityCenterClient)
        mock_client.delete_application_assignment = Mock(
            side_effect=IdentityCenterClientError("Generic error occurred")
        )
        
        result = delete_application_assignment(
            application_arn="arn:aws:sso:::123456789012:instance/test/application/test",
            principal_id="12345678-1234-1234-1234-123456789012",
            principal_type="USER",
            client=mock_client
        )
        
        # Verify failure is captured
        assert result.success is False
        assert result.error_message is not None
        assert "Generic error occurred" in result.error_message
        assert result.error_code is not None
    
    def test_unexpected_exception_is_handled(self):
        """
        Test that unexpected exceptions are caught and handled gracefully.
        
        _Requirements: 5.3, 5.5_
        """
        # Create mock client that raises unexpected exception
        mock_client = Mock(spec=IdentityCenterClient)
        mock_client.delete_application_assignment = Mock(
            side_effect=RuntimeError("Unexpected runtime error")
        )
        
        # Attempt deletion
        result = delete_application_assignment(
            application_arn="arn:aws:sso:::123456789012:instance/test/application/test",
            principal_id="12345678-1234-1234-1234-123456789012",
            principal_type="GROUP",
            client=mock_client
        )
        
        # Verify unexpected error is handled
        assert result.success is False
        assert result.error_message is not None
        assert "Unexpected error" in result.error_message
        assert result.error_code == 'UnexpectedError'
    
    def test_deletion_result_to_dict(self):
        """
        Test that DeletionResult can be converted to dictionary format.
        
        _Requirements: 5.4_
        """
        # Test successful result
        success_result = DeletionResult(
            success=True,
            application_arn="arn:aws:sso:::123456789012:instance/test/application/test",
            principal_id="12345678-1234-1234-1234-123456789012",
            principal_type="GROUP"
        )
        
        success_dict = success_result.to_dict()
        assert success_dict['success'] is True
        assert success_dict['application_arn'] == "arn:aws:sso:::123456789012:instance/test/application/test"
        assert success_dict['principal_id'] == "12345678-1234-1234-1234-123456789012"
        assert success_dict['principal_type'] == "GROUP"
        assert 'error_message' not in success_dict
        assert 'error_code' not in success_dict
        
        # Test failure result
        failure_result = DeletionResult(
            success=False,
            application_arn="arn:aws:sso:::123456789012:instance/test/application/test",
            principal_id="12345678-1234-1234-1234-123456789012",
            principal_type="USER",
            error_message="Access denied",
            error_code="AccessDeniedException"
        )
        
        failure_dict = failure_result.to_dict()
        assert failure_dict['success'] is False
        assert failure_dict['error_message'] == "Access denied"
        assert failure_dict['error_code'] == "AccessDeniedException"


