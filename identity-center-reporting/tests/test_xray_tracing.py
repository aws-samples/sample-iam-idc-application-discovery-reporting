"""
Tests for X-Ray tracing in matching operations.

This module contains unit tests for X-Ray tracing functionality added to
the matching logic and application name caching.
"""

from unittest.mock import patch, MagicMock, Mock
import sys
import os

# Add the lambdas directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'assignment-discovery'))

# Import matching module
import matching


# ============================================================================
# Unit Tests for X-Ray Tracing in Matching Logic
# ============================================================================

def test_subsegment_created_for_matching():
    """
    Test that an X-Ray subsegment is created for matching evaluation.
    Validates: Task 8 - X-Ray tracing for matching operations
    """
    # Disable metrics for this test
    original_metrics_enabled = matching._metrics_enabled
    matching._metrics_enabled = False
    
    # Store original XRAY_AVAILABLE value
    original_xray_available = matching.XRAY_AVAILABLE
    
    try:
        # Mock X-Ray recorder
        mock_recorder = MagicMock()
        mock_subsegment = MagicMock()
        # Make begin_subsegment return the mock subsegment without raising exceptions
        mock_recorder.begin_subsegment.return_value = mock_subsegment
        
        # Patch XRAY_AVAILABLE and xray_recorder
        matching.XRAY_AVAILABLE = True
        matching.xray_recorder = mock_recorder
        
        from matching import evaluate_group_application_match
        
        result = evaluate_group_application_match('GROUP', 'Engineering', 'Engineering-Portal')
        
        # Verify subsegment was created
        mock_recorder.begin_subsegment.assert_called_once_with('matching_evaluation')
        
        # Verify subsegment was ended
        mock_recorder.end_subsegment.assert_called_once()
        
        assert result == 'Yes'
    finally:
        matching._metrics_enabled = original_metrics_enabled
        matching.XRAY_AVAILABLE = original_xray_available


def test_annotations_added_for_matching_result():
    """
    Test that annotations are added to the X-Ray subsegment for matching results.
    Validates: Task 8 - X-Ray tracing for matching operations
    """
    # Disable metrics for this test
    original_metrics_enabled = matching._metrics_enabled
    matching._metrics_enabled = False
    
    # Store original XRAY_AVAILABLE value
    original_xray_available = matching.XRAY_AVAILABLE
    
    try:
        # Mock X-Ray recorder
        mock_recorder = MagicMock()
        mock_subsegment = MagicMock()
        mock_recorder.begin_subsegment.return_value = mock_subsegment
        
        # Patch XRAY_AVAILABLE and xray_recorder
        matching.XRAY_AVAILABLE = True
        matching.xray_recorder = mock_recorder
        
        from matching import evaluate_group_application_match
        
        result = evaluate_group_application_match('GROUP', 'Engineering', 'Engineering-Portal')
        
        # Verify annotations were added
        assert mock_subsegment.put_annotation.called, "Expected annotations to be added"
        
        # Check for specific annotations
        annotation_calls = mock_subsegment.put_annotation.call_args_list
        annotation_dict = {call[0][0]: call[0][1] for call in annotation_calls}
        
        assert 'principal_type' in annotation_dict, "Expected principal_type annotation"
        assert annotation_dict['principal_type'] == 'GROUP'
        
        assert 'has_principal_name' in annotation_dict, "Expected has_principal_name annotation"
        assert annotation_dict['has_principal_name'] is True
        
        assert 'has_application_name' in annotation_dict, "Expected has_application_name annotation"
        assert annotation_dict['has_application_name'] is True
        
        assert 'matching_result' in annotation_dict, "Expected matching_result annotation"
        assert annotation_dict['matching_result'] == 'Yes'
        
        assert result == 'Yes'
    finally:
        matching._metrics_enabled = original_metrics_enabled
        matching.XRAY_AVAILABLE = original_xray_available


def test_metadata_added_for_matching_details():
    """
    Test that metadata is added to the X-Ray subsegment with matching details.
    Validates: Task 8 - X-Ray tracing for matching operations
    """
    # Disable metrics for this test
    original_metrics_enabled = matching._metrics_enabled
    matching._metrics_enabled = False
    
    # Store original XRAY_AVAILABLE value
    original_xray_available = matching.XRAY_AVAILABLE
    
    try:
        # Mock X-Ray recorder
        mock_recorder = MagicMock()
        mock_subsegment = MagicMock()
        mock_recorder.begin_subsegment.return_value = mock_subsegment
        
        # Patch XRAY_AVAILABLE and xray_recorder
        matching.XRAY_AVAILABLE = True
        matching.xray_recorder = mock_recorder
        
        from matching import evaluate_group_application_match
        
        result = evaluate_group_application_match('GROUP', 'Engineering', 'Engineering-Portal')
        
        # Verify metadata was added
        assert mock_subsegment.put_metadata.called, "Expected metadata to be added"
        
        # Check metadata content
        metadata_call = mock_subsegment.put_metadata.call_args
        assert metadata_call[0][0] == 'matching_details'
        
        metadata_content = metadata_call[0][1]
        assert 'principal_name' in metadata_content
        assert metadata_content['principal_name'] == 'Engineering'
        assert 'application_name' in metadata_content
        assert metadata_content['application_name'] == 'Engineering-Portal'
        assert 'result' in metadata_content
        assert metadata_content['result'] == 'Yes'
        
        assert result == 'Yes'
    finally:
        matching._metrics_enabled = original_metrics_enabled
        matching.XRAY_AVAILABLE = original_xray_available


def test_xray_unavailable_does_not_break_matching():
    """
    Test that matching works when X-Ray is not available.
    Validates: Task 8 - X-Ray tracing for matching operations
    """
    # Disable metrics for this test
    original_metrics_enabled = matching._metrics_enabled
    matching._metrics_enabled = False
    
    try:
        with patch.object(matching, 'XRAY_AVAILABLE', False):
            from matching import evaluate_group_application_match
            
            result = evaluate_group_application_match('GROUP', 'Engineering', 'Engineering-Portal')
            
            # Matching should still work without X-Ray
            assert result == 'Yes', "Matching should work even when X-Ray is unavailable"
    finally:
        matching._metrics_enabled = original_metrics_enabled


def test_subsegment_exception_handling():
    """
    Test that exceptions during subsegment operations don't break matching.
    Validates: Task 8 - X-Ray tracing for matching operations
    """
    # Disable metrics for this test
    original_metrics_enabled = matching._metrics_enabled
    matching._metrics_enabled = False
    
    try:
        # Mock X-Ray recorder to raise exception
        mock_recorder = MagicMock()
        mock_recorder.begin_subsegment.side_effect = Exception("X-Ray error")
        
        with patch.object(matching, 'XRAY_AVAILABLE', True):
            with patch.object(matching, 'xray_recorder', mock_recorder):
                from matching import evaluate_group_application_match
                
                result = evaluate_group_application_match('GROUP', 'Engineering', 'Engineering-Portal')
                
                # Matching should still work despite X-Ray error
                assert result == 'Yes', "Matching should work even if X-Ray subsegment creation fails"
    finally:
        matching._metrics_enabled = original_metrics_enabled
