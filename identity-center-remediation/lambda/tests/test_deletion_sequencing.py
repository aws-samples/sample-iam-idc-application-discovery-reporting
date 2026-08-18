"""
Property-based tests for deletion sequencing.

**Feature: identity-center-app-monitor, Property 8: Deletion precedes notification**
**Validates: Requirements 5.2**
"""

import pytest
from hypothesis import given, strategies as st, settings
from unittest.mock import Mock, MagicMock, call
from deletion import delete_application_assignment, DeletionResult
from identity_center_client import IdentityCenterClient, IdentityCenterClientError


# Strategy for generating valid ARNs
@st.composite
def application_arn_strategy(draw):
    """Generate valid application ARNs."""
    account_id = draw(st.integers(min_value=100000000000, max_value=999999999999))
    instance_id = draw(st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), min_codepoint=48, max_codepoint=122),
        min_size=10,
        max_size=20
    ))
    app_id = draw(st.text(
        alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), min_codepoint=48, max_codepoint=122),
        min_size=10,
        max_size=20
    ))
    return f"arn:aws:sso:::{account_id}:instance/{instance_id}/application/{app_id}"


# Strategy for generating principal IDs (UUIDs)
@st.composite
def principal_id_strategy(draw):
    """Generate valid principal IDs (UUID format)."""
    parts = [
        draw(st.text(alphabet='0123456789abcdef', min_size=8, max_size=8)),
        draw(st.text(alphabet='0123456789abcdef', min_size=4, max_size=4)),
        draw(st.text(alphabet='0123456789abcdef', min_size=4, max_size=4)),
        draw(st.text(alphabet='0123456789abcdef', min_size=4, max_size=4)),
        draw(st.text(alphabet='0123456789abcdef', min_size=12, max_size=12))
    ]
    return '-'.join(parts)


class TestDeletionSequencing:
    """Tests for deletion sequencing and ordering."""
    
    @given(
        application_arn=application_arn_strategy(),
        principal_id=principal_id_strategy(),
        principal_type=st.sampled_from(['USER', 'GROUP'])
    )
    @settings(max_examples=100)
    def test_deletion_completes_before_returning_result(
        self,
        application_arn,
        principal_id,
        principal_type
    ):
        """
        **Property 8: Deletion precedes notification**
        
        For any application assignment deletion, the delete API call
        should complete (successfully or with error) before the function
        returns a result.
        
        This test verifies that the deletion operation is synchronous
        and completes before returning control to the caller.
        """
        # Create a mock client
        mock_client = Mock(spec=IdentityCenterClient)
        
        # Track whether delete was called
        delete_called = False
        
        def mock_delete(*args, **kwargs):
            nonlocal delete_called
            delete_called = True
            return {}
        
        mock_client.delete_application_assignment = Mock(side_effect=mock_delete)
        
        # Call deletion function
        result = delete_application_assignment(
            application_arn=application_arn,
            principal_id=principal_id,
            principal_type=principal_type,
            client=mock_client
        )
        
        # Verify delete was called before we got the result
        assert delete_called is True
        
        # Verify we got a result
        assert isinstance(result, DeletionResult)
        assert result.application_arn == application_arn
        assert result.principal_id == principal_id
        assert result.principal_type == principal_type
    
    @given(
        application_arn=application_arn_strategy(),
        principal_id=principal_id_strategy(),
        principal_type=st.sampled_from(['USER', 'GROUP'])
    )
    @settings(max_examples=100)
    def test_successful_deletion_returns_success_result(
        self,
        application_arn,
        principal_id,
        principal_type
    ):
        """
        **Property 8: Deletion precedes notification**
        
        For any successful deletion, the function should return
        a DeletionResult with success=True after the deletion completes.
        """
        # Create a mock client that succeeds
        mock_client = Mock(spec=IdentityCenterClient)
        mock_client.delete_application_assignment = Mock(return_value={})
        
        # Call deletion function
        result = delete_application_assignment(
            application_arn=application_arn,
            principal_id=principal_id,
            principal_type=principal_type,
            client=mock_client
        )
        
        # Verify deletion was called
        mock_client.delete_application_assignment.assert_called_once()
        
        # Verify result indicates success
        assert result.success is True
        assert result.error_message is None
    
    @given(
        application_arn=application_arn_strategy(),
        principal_id=principal_id_strategy(),
        principal_type=st.sampled_from(['USER', 'GROUP']),
        error_message=st.text(min_size=1, max_size=100)
    )
    @settings(max_examples=100)
    def test_failed_deletion_returns_error_result(
        self,
        application_arn,
        principal_id,
        principal_type,
        error_message
    ):
        """
        **Property 8: Deletion precedes notification**
        
        For any failed deletion, the function should return
        a DeletionResult with success=False and error details
        after the deletion attempt completes.
        """
        # Create a mock client that fails
        mock_client = Mock(spec=IdentityCenterClient)
        mock_client.delete_application_assignment = Mock(
            side_effect=IdentityCenterClientError(error_message)
        )
        
        # Call deletion function
        result = delete_application_assignment(
            application_arn=application_arn,
            principal_id=principal_id,
            principal_type=principal_type,
            client=mock_client
        )
        
        # Verify deletion was attempted
        mock_client.delete_application_assignment.assert_called()
        
        # Verify result indicates failure with error details
        assert result.success is False
        assert result.error_message is not None
        assert len(result.error_message) > 0
    
    @given(
        application_arn=application_arn_strategy(),
        principal_id=principal_id_strategy(),
        principal_type=st.sampled_from(['USER', 'GROUP'])
    )
    @settings(max_examples=100)
    def test_deletion_result_contains_all_required_fields(
        self,
        application_arn,
        principal_id,
        principal_type
    ):
        """
        **Property 8: Deletion precedes notification**
        
        For any deletion operation, the returned DeletionResult
        should contain all required fields (application_arn, principal_id,
        principal_type, success status).
        """
        # Create a mock client
        mock_client = Mock(spec=IdentityCenterClient)
        mock_client.delete_application_assignment = Mock(return_value={})
        
        # Call deletion function
        result = delete_application_assignment(
            application_arn=application_arn,
            principal_id=principal_id,
            principal_type=principal_type,
            client=mock_client
        )
        
        # Verify all required fields are present
        assert hasattr(result, 'success')
        assert hasattr(result, 'application_arn')
        assert hasattr(result, 'principal_id')
        assert hasattr(result, 'principal_type')
        
        # Verify field values match input
        assert result.application_arn == application_arn
        assert result.principal_id == principal_id
        assert result.principal_type == principal_type
        
        # Verify result can be converted to dict
        result_dict = result.to_dict()
        assert 'success' in result_dict
        assert 'application_arn' in result_dict
        assert 'principal_id' in result_dict
        assert 'principal_type' in result_dict


class TestDeletionOrdering:
    """Tests for ensuring deletion happens in correct order."""
    
    def test_deletion_api_called_exactly_once_on_success(self):
        """
        **Property 8: Deletion precedes notification**
        
        For any successful deletion, the delete API should be called
        exactly once before returning the result.
        """
        mock_client = Mock(spec=IdentityCenterClient)
        mock_client.delete_application_assignment = Mock(return_value={})
        
        result = delete_application_assignment(
            application_arn="arn:aws:sso:::123456789012:instance/test/application/test",
            principal_id="12345678-1234-1234-1234-123456789012",
            principal_type="GROUP",
            client=mock_client
        )
        
        # Verify API was called exactly once
        assert mock_client.delete_application_assignment.call_count == 1
        
        # Verify result indicates success
        assert result.success is True
    
    def test_deletion_retries_on_transient_errors(self):
        """
        **Property 8: Deletion precedes notification**
        
        For any deletion that fails with transient errors,
        the system should retry before returning the final result.
        """
        mock_client = Mock(spec=IdentityCenterClient)
        
        # Simulate transient error followed by success
        call_count = 0
        
        def mock_delete(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                # First call fails with throttling
                from botocore.exceptions import ClientError
                raise ClientError(
                    error_response={
                        'Error': {
                            'Code': 'ThrottlingException',
                            'Message': 'Rate exceeded'
                        }
                    },
                    operation_name='DeleteApplicationAssignment'
                )
            # Second call succeeds
            return {}
        
        mock_client.delete_application_assignment = Mock(side_effect=mock_delete)
        
        result = delete_application_assignment(
            application_arn="arn:aws:sso:::123456789012:instance/test/application/test",
            principal_id="12345678-1234-1234-1234-123456789012",
            principal_type="GROUP",
            client=mock_client
        )
        
        # Verify API was called multiple times (retry happened)
        assert mock_client.delete_application_assignment.call_count >= 2
        
        # Verify final result indicates success
        assert result.success is True
