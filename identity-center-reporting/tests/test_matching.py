"""
Tests for SSO Group-Application matching logic.

This module contains both property-based tests and unit tests for the
matching logic that evaluates whether group names and application names
match using symmetric whole-word (token) matching.
"""

import logging
from hypothesis import given, strategies as st, settings
from unittest.mock import patch, MagicMock
import sys
import os

# Add path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'assignment-discovery'))

# Import matching module
import matching
from matching import evaluate_group_application_match


# ============================================================================
# Property-Based Tests
# ============================================================================

@given(
    group_name=st.text(min_size=1, max_size=50, alphabet=st.characters(blacklist_categories=('Cs',))),
    app_name=st.text(min_size=1, max_size=100, alphabet=st.characters(blacklist_categories=('Cs',)))
)
@settings(max_examples=100, deadline=None)
def test_property_1_case_insensitive_matching(group_name, app_name):
    """
    Feature: sso-group-application-matching, Property 1: Case-insensitive matching for groups
    Validates: Requirements 1.1
    
    For any group assignment with valid principal_name and application_name,
    the matching result should be the same regardless of the case of the strings.
    """
    # Disable metrics for property tests to avoid performance issues
    original_metrics_enabled = matching._metrics_enabled
    matching._metrics_enabled = False
    
    try:
        # Skip if either string is whitespace-only
        if not group_name.strip() or not app_name.strip():
            return
        
        # Test that matching is case-insensitive
        result_lower = evaluate_group_application_match('GROUP', group_name.lower(), app_name.lower())
        result_upper = evaluate_group_application_match('GROUP', group_name.upper(), app_name.upper())
        result_mixed = evaluate_group_application_match('GROUP', group_name, app_name)
        
        # All should produce the same result (Yes or No, not Unknown)
        assert result_lower in ['Yes', 'No'], f"Unexpected result: {result_lower}"
        assert result_upper in ['Yes', 'No'], f"Unexpected result: {result_upper}"
        assert result_mixed in ['Yes', 'No'], f"Unexpected result: {result_mixed}"
        assert result_lower == result_upper == result_mixed, \
            f"Case-insensitive matching failed: lower={result_lower}, upper={result_upper}, mixed={result_mixed}"
    finally:
        matching._metrics_enabled = original_metrics_enabled


@given(
    group_name=st.text(min_size=1, max_size=50, alphabet=st.characters(blacklist_categories=('Cs',))),
    app_name=st.text(min_size=1, max_size=100, alphabet=st.characters(blacklist_categories=('Cs',)))
)
@settings(max_examples=100, deadline=None)
def test_property_2_no_match_produces_no(group_name, app_name):
    """
    Feature: sso-group-application-matching, Property 2: No match produces 'No' metadata
    Validates: Requirements 1.2

    For any group assignment where neither the principal_name's tokens nor the
    application_name's tokens appear as a contiguous whole-word (token) run
    within the other side's tokens (symmetric matching), the result should be
    'No'.
    """
    # Disable metrics for property tests
    original_metrics_enabled = matching._metrics_enabled
    matching._metrics_enabled = False

    try:
        # Skip if either string is whitespace-only
        if not group_name.strip() or not app_name.strip():
            return

        # These substring skips are a superset of the symmetric whole-word match
        # set (either direction), so any pair that survives both checks is a
        # genuine non-match under symmetric whole-word rules too.
        if group_name.lower() in app_name.lower() or app_name.lower() in group_name.lower():
            return  # Skip this case, it's a match
        
        result = evaluate_group_application_match('GROUP', group_name, app_name)
        
        assert result == 'No', \
            f"Expected 'No' for non-matching pair, got '{result}' for group='{group_name}', app='{app_name}'"
    finally:
        matching._metrics_enabled = original_metrics_enabled


# Exclude delimiter characters ('-', '_', and all Unicode whitespace/separator
# categories that Python's regex \s matches) from generated tokens so embedding
# them alongside the group value keeps the group a WHOLE token in the
# constructed application name (not a raw substring straddling delimiters).
_TOKEN_ALPHABET = st.characters(
    blacklist_categories=('Cs', 'Cc', 'Zs', 'Zl', 'Zp'),
    blacklist_characters='-_'
)


@given(
    group=st.text(min_size=1, max_size=30, alphabet=_TOKEN_ALPHABET),
    prefix_token=st.text(min_size=0, max_size=30, alphabet=_TOKEN_ALPHABET),
    suffix_token=st.text(min_size=0, max_size=30, alphabet=_TOKEN_ALPHABET)
)
@settings(max_examples=100, deadline=None)
def test_property_3_match_produces_yes(group, prefix_token, suffix_token):
    """
    Feature: sso-group-application-matching, Property 3: Match produces 'Yes' metadata
    Validates: Requirements 1.3

    For any group assignment where the principal_name is embedded as a whole
    delimiter-separated TOKEN within the application_name (case-insensitive),
    the result should be 'Yes'. Corrected from raw substring embedding to
    whole-token embedding to match the whole-word matching fix.
    """
    # Disable metrics for property tests
    original_metrics_enabled = matching._metrics_enabled
    matching._metrics_enabled = False

    try:
        # Skip if group is whitespace-only
        if not group.strip():
            return

        # Embed group as a whole hyphen-delimited token, not a raw substring.
        parts = [p for p in (prefix_token, group, suffix_token) if p.strip()]
        app_name = '-'.join(parts)

        # Skip if app_name ends up being whitespace-only
        if not app_name.strip():
            return

        result = evaluate_group_application_match('GROUP', group, app_name)

        assert result == 'Yes', \
            f"Expected 'Yes' for matching pair, got '{result}' for group='{group}', app='{app_name}'"
    finally:
        matching._metrics_enabled = original_metrics_enabled


@given(
    user_name=st.text(min_size=1, max_size=50, alphabet=st.characters(blacklist_categories=('Cs',))),
    app_name=st.text(min_size=1, max_size=100, alphabet=st.characters(blacklist_categories=('Cs',)))
)
@settings(max_examples=100, deadline=None)
def test_property_4_user_assignments_no_metadata(user_name, app_name):
    """
    Feature: sso-group-application-matching, Property 4: User assignments have no matching metadata
    Validates: Requirements 1.4
    
    For any assignment with principal_type='USER', the result should be
    an empty string (no matching performed).
    """
    # Disable metrics for property tests
    original_metrics_enabled = matching._metrics_enabled
    matching._metrics_enabled = False
    
    try:
        result = evaluate_group_application_match('USER', user_name, app_name)
        
        assert result == '', \
            f"Expected empty string for USER principal, got '{result}'"
    finally:
        matching._metrics_enabled = original_metrics_enabled


@given(
    group_name=st.text(min_size=1, max_size=50, alphabet=st.characters(blacklist_categories=('Cs',))),
    app_name=st.text(min_size=1, max_size=100, alphabet=st.characters(blacklist_categories=('Cs',)))
)
@settings(max_examples=100, deadline=None)
def test_property_7_exception_handling_produces_unknown(group_name, app_name):
    """
    Feature: sso-group-application-matching, Property 7: Exception handling produces 'Unknown'
    Validates: Requirements 3.4
    
    For any matching evaluation that raises an exception, the result should
    be 'Unknown' and an error should be logged.
    """
    # Disable metrics for property tests
    original_metrics_enabled = matching._metrics_enabled
    matching._metrics_enabled = False
    
    try:
        # Skip if either string is whitespace-only (these are handled normally)
        if not group_name.strip() or not app_name.strip():
            return
        
        # Create a mock object that raises an exception when lower() is called
        mock_principal = MagicMock()
        mock_principal.strip.return_value = "valid"
        mock_principal.lower.side_effect = Exception("Simulated error")
        
        with patch.object(matching, 'logger') as mock_logger:
            result = evaluate_group_application_match('GROUP', mock_principal, app_name)
            
            assert result == 'Unknown', \
                f"Expected 'Unknown' for exception case, got '{result}'"
            
            # Verify error was logged
            assert mock_logger.error.called, "Expected error to be logged"
    finally:
        matching._metrics_enabled = original_metrics_enabled


# ============================================================================
# Unit Tests for Edge Cases
# ============================================================================

def test_none_principal_name_returns_no():
    """
    Test that None principal_name returns 'No'.
    Validates: Requirements 3.1
    """
    result = evaluate_group_application_match('GROUP', None, 'SomeApp')
    assert result == 'No', f"Expected 'No' for None principal_name, got '{result}'"


def test_empty_principal_name_returns_no():
    """
    Test that empty principal_name returns 'No'.
    Validates: Requirements 3.1
    """
    result = evaluate_group_application_match('GROUP', '', 'SomeApp')
    assert result == 'No', f"Expected 'No' for empty principal_name, got '{result}'"


def test_none_application_name_returns_no():
    """
    Test that None application_name returns 'No'.
    Validates: Requirements 3.2
    """
    result = evaluate_group_application_match('GROUP', 'SomeGroup', None)
    assert result == 'No', f"Expected 'No' for None application_name, got '{result}'"


def test_empty_application_name_returns_no():
    """
    Test that empty application_name returns 'No'.
    Validates: Requirements 3.2
    """
    result = evaluate_group_application_match('GROUP', 'SomeGroup', '')
    assert result == 'No', f"Expected 'No' for empty application_name, got '{result}'"


def test_whitespace_only_principal_name_returns_no():
    """
    Test that whitespace-only principal_name returns 'No'.
    Validates: Requirements 3.3
    """
    result = evaluate_group_application_match('GROUP', '   ', 'SomeApp')
    assert result == 'No', f"Expected 'No' for whitespace-only principal_name, got '{result}'"


def test_whitespace_only_application_name_returns_no():
    """
    Test that whitespace-only application_name returns 'No'.
    Validates: Requirements 3.3
    """
    result = evaluate_group_application_match('GROUP', 'SomeGroup', '   ')
    assert result == 'No', f"Expected 'No' for whitespace-only application_name, got '{result}'"


def test_both_whitespace_only_returns_no():
    """
    Test that both whitespace-only strings return 'No'.
    Validates: Requirements 3.3
    """
    result = evaluate_group_application_match('GROUP', '   ', '   ')
    assert result == 'No', f"Expected 'No' for both whitespace-only, got '{result}'"


def test_special_characters_in_names():
    """
    Test that special characters in names are handled correctly under
    whole-word (token) matching rules.
    Validates: Requirements 3.5
    """
    # Test with various special characters; each expected value is recomputed
    # for whole-word matching (tokens split only on '-', '_', whitespace).
    test_cases = [
        # tokens ['admin'] / ['admin', 'portal'] -> whole first-token match
        ('Admin', 'Admin-Portal', 'Yes'),
        # tokens ['admin', 'group'] / ['admin', 'portal', 'app'] -> not contiguous
        ('Admin_Group', 'Admin_Portal_App', 'No'),
        # CORRECTED: '.' is not a delimiter, so tokens are ['admin.group'] /
        # ['admin.group.portal'] -> single app token is not equal to the group
        # token (it's a superset string), so this is 'No' under whole-word
        # rules even though it was a raw substring match (previously 'Yes').
        ('Admin.Group', 'Admin.Group.Portal', 'No'),
        # '@' is not a delimiter, but '-' is: tokens ['admin@group'] /
        # ['admin@group', 'app'] -> whole first-token match
        ('Admin@Group', 'Admin@Group-App', 'Yes'),
        # '#' is not a delimiter, but '-' is: tokens ['admin#123'] /
        # ['admin#123', 'portal'] -> whole first-token match
        ('Admin#123', 'Admin#123-Portal', 'Yes'),
        # '$' is not a delimiter, but '-' is: tokens ['admin$group'] /
        # ['portal', 'admin$group'] -> whole last-token match
        ('Admin$Group', 'Portal-Admin$Group', 'Yes'),
        # tokens ['admin%group'] / ['someotherapp'] -> no match
        ('Admin%Group', 'SomeOtherApp', 'No'),
        # tokens ['group', 'name'] / ['app', 'group', 'name', 'portal'] ->
        # contiguous interior whole-token match
        ('Group-Name', 'App-Group-Name-Portal', 'Yes'),
        # tokens ['name', 'with', 'underscores'] /
        # ['app', 'name', 'with', 'underscores'] -> contiguous whole-token match
        ('Name_With_Underscores', 'App_Name_With_Underscores', 'Yes'),
    ]

    for group_name, app_name, expected in test_cases:
        result = evaluate_group_application_match('GROUP', group_name, app_name)
        assert result == expected, \
            f"Expected '{expected}' for group='{group_name}', app='{app_name}', got '{result}'"


def test_exact_match():
    """Test exact match between group name and application name."""
    result = evaluate_group_application_match('GROUP', 'Engineering', 'Engineering')
    assert result == 'Yes', f"Expected 'Yes' for exact match, got '{result}'"


def test_partial_match():
    """
    Test that a raw substring/prefix match is correctly rejected.

    CORRECTED EXPECTATION: previously this test asserted 'Yes', encoding the
    fail-open substring bug ('Eng' is a substring of 'Engineering-Portal').
    Under whole-word matching, 'Eng' is not a whole token of
    ['engineering', 'portal'], so the correct result is 'No'.
    """
    result = evaluate_group_application_match('GROUP', 'Eng', 'Engineering-Portal')
    assert result == 'No', f"Expected 'No' for prefix-only fail-open probe, got '{result}'"


def test_no_match():
    """Test no match between group name and application name."""
    result = evaluate_group_application_match('GROUP', 'Sales', 'Engineering-Portal')
    assert result == 'No', f"Expected 'No' for no match, got '{result}'"


def test_whole_word_match_first_position():
    """Whole-word match at the first token position -> 'Yes'."""
    result = evaluate_group_application_match('GROUP', 'Sales', 'Sales-Engineering')
    assert result == 'Yes', f"Expected 'Yes' for first-position whole-word match, got '{result}'"


def test_whole_word_match_last_position():
    """Whole-word match at the last token position -> 'Yes'."""
    result = evaluate_group_application_match('GROUP', 'Portal', 'Engineering-Portal')
    assert result == 'Yes', f"Expected 'Yes' for last-position whole-word match, got '{result}'"


def test_whole_word_match_interior_position():
    """Whole-word match at an interior token position -> 'Yes'."""
    result = evaluate_group_application_match('GROUP', 'Data', 'Prod-Data-Science')
    assert result == 'Yes', f"Expected 'Yes' for interior-position whole-word match, got '{result}'"


def test_prefix_only_fail_open_probes_return_no():
    """
    Regression tests for the fail-open substring bug: a group name that is
    merely a prefix/substring of an application token (not equal to a whole
    token) must NOT be reported as a match.
    """
    test_cases = [
        ('Eng', 'Engineering-Portal'),  # 'eng' != whole tokens ['engineering', 'portal']
        ('C', 'CustomerPortal'),  # 'c' != whole token ['customerportal']
        ('ale', 'Sales-Eng'),  # 'ale' != whole tokens ['sales', 'eng']
    ]
    for group_name, app_name in test_cases:
        result = evaluate_group_application_match('GROUP', group_name, app_name)
        assert result == 'No', \
            f"Expected 'No' for prefix-only fail-open probe group='{group_name}', app='{app_name}', got '{result}'"


def test_multi_word_contiguous_match():
    """A multi-token group value must match as a contiguous run in the app tokens."""
    result = evaluate_group_application_match('GROUP', 'Data Science', 'Prod-Data-Science')
    assert result == 'Yes', f"Expected 'Yes' for multi-word contiguous match, got '{result}'"


def test_underscore_delimited_whole_word_match():
    """Underscore-delimited whole-word match -> 'Yes'."""
    result = evaluate_group_application_match('GROUP', 'Admin_Group', 'Admin_Group_Portal')
    assert result == 'Yes', f"Expected 'Yes' for underscore-delimited whole-word match, got '{result}'"


def test_case_insensitive_match():
    """Test case-insensitive matching."""
    test_cases = [
        ('engineering', 'Engineering-Portal', 'Yes'),
        ('ENGINEERING', 'engineering-portal', 'Yes'),
        ('EnGiNeErInG', 'ENGINEERING-PORTAL', 'Yes'),
    ]
    
    for group_name, app_name, expected in test_cases:
        result = evaluate_group_application_match('GROUP', group_name, app_name)
        assert result == expected, \
            f"Expected '{expected}' for group='{group_name}', app='{app_name}', got '{result}'"


def test_user_principal_returns_empty_string():
    """Test that USER principals return empty string."""
    result = evaluate_group_application_match('USER', 'john.doe', 'SomeApp')
    assert result == '', f"Expected empty string for USER principal, got '{result}'"


def test_exception_handling_with_logging():
    """
    Test that exceptions are caught and logged properly.
    Validates: Requirements 3.4
    """
    
    # Create a mock that raises an exception when lower() is called
    mock_principal = MagicMock()
    mock_principal.strip.return_value = "valid"
    mock_principal.lower.side_effect = Exception("Test exception")
    
    with patch.object(matching, 'logger') as mock_logger:
        result = evaluate_group_application_match('GROUP', mock_principal, 'SomeApp')
        
        assert result == 'Unknown', f"Expected 'Unknown' for exception, got '{result}'"
        assert mock_logger.error.called, "Expected error to be logged"
        
        # Verify the error message contains relevant information
        error_call = mock_logger.error.call_args[0][0]
        assert 'Matching evaluation failed' in error_call
        assert 'principal_type' in error_call
        assert 'error' in error_call


# ============================================================================
# Unit Tests for CloudWatch Metrics Emission
# ============================================================================

def test_metrics_emitted_for_yes_match():
    """
    Test that metrics are emitted for a 'Yes' match result.
    Validates: Task 7 - CloudWatch metrics emission
    """
    
    # Create mock CloudWatch client
    mock_cloudwatch = MagicMock()
    
    # Patch the _get_cloudwatch_client function to return our mock
    with patch.object(matching, '_get_cloudwatch_client', return_value=mock_cloudwatch):
        result = evaluate_group_application_match('GROUP', 'Engineering', 'Engineering-Portal')
        
        assert result == 'Yes'
        assert mock_cloudwatch.put_metric_data.called, "Expected metrics to be emitted"
        
        # Verify the metric data
        call_args = mock_cloudwatch.put_metric_data.call_args
        assert call_args[1]['Namespace'] == 'IAMIdentityCenter/Discovery'
        
        metric_data = call_args[1]['MetricData']
        metric_names = [m['MetricName'] for m in metric_data]
        
        assert 'MatchingEvaluations' in metric_names, "Expected MatchingEvaluations metric"
        assert 'MatchedYes' in metric_names, "Expected MatchedYes metric"
        assert 'MatchedNo' not in metric_names, "Should not emit MatchedNo for Yes result"
        assert 'MatchingErrors' not in metric_names, "Should not emit MatchingErrors for successful match"


def test_metrics_emitted_for_no_match():
    """
    Test that metrics are emitted for a 'No' match result.
    Validates: Task 7 - CloudWatch metrics emission
    """
    
    # Create mock CloudWatch client
    mock_cloudwatch = MagicMock()
    
    # Patch the _get_cloudwatch_client function to return our mock
    with patch.object(matching, '_get_cloudwatch_client', return_value=mock_cloudwatch):
        result = evaluate_group_application_match('GROUP', 'Sales', 'Engineering-Portal')
        
        assert result == 'No'
        assert mock_cloudwatch.put_metric_data.called, "Expected metrics to be emitted"
        
        # Verify the metric data
        call_args = mock_cloudwatch.put_metric_data.call_args
        assert call_args[1]['Namespace'] == 'IAMIdentityCenter/Discovery'
        
        metric_data = call_args[1]['MetricData']
        metric_names = [m['MetricName'] for m in metric_data]
        
        assert 'MatchingEvaluations' in metric_names, "Expected MatchingEvaluations metric"
        assert 'MatchedNo' in metric_names, "Expected MatchedNo metric"
        assert 'MatchedYes' not in metric_names, "Should not emit MatchedYes for No result"
        assert 'MatchingErrors' not in metric_names, "Should not emit MatchingErrors for successful match"


def test_metrics_emitted_for_unknown_result():
    """
    Test that metrics are emitted for an 'Unknown' result (exception case).
    Validates: Task 7 - CloudWatch metrics emission
    """
    
    # Create mock CloudWatch client
    mock_cloudwatch = MagicMock()
    
    # Create a mock that raises an exception
    mock_principal = MagicMock()
    mock_principal.strip.return_value = "valid"
    mock_principal.lower.side_effect = Exception("Test exception")
    
    # Patch both the CloudWatch client and logger
    with patch.object(matching, '_get_cloudwatch_client', return_value=mock_cloudwatch), \
         patch.object(matching, 'logger'):
        result = evaluate_group_application_match('GROUP', mock_principal, 'SomeApp')
    
    assert result == 'Unknown'
    assert mock_cloudwatch.put_metric_data.called, "Expected metrics to be emitted"
    
    # Verify the metric data
    call_args = mock_cloudwatch.put_metric_data.call_args
    assert call_args[1]['Namespace'] == 'IAMIdentityCenter/Discovery'
    
    metric_data = call_args[1]['MetricData']
    metric_names = [m['MetricName'] for m in metric_data]
    
    assert 'MatchingEvaluations' in metric_names, "Expected MatchingEvaluations metric"
    assert 'MatchedUnknown' in metric_names, "Expected MatchedUnknown metric"
    assert 'MatchingErrors' in metric_names, "Expected MatchingErrors metric for exception"
    assert 'MatchedYes' not in metric_names, "Should not emit MatchedYes for Unknown result"
    assert 'MatchedNo' not in metric_names, "Should not emit MatchedNo for Unknown result"


def test_metrics_not_emitted_for_user_principals():
    """
    Test that metrics are not emitted for USER principals.
    Validates: Task 7 - CloudWatch metrics emission
    """
    
    # Create mock CloudWatch client
    mock_cloudwatch = MagicMock()
    
    # Patch the _get_cloudwatch_client function to return our mock
    with patch.object(matching, '_get_cloudwatch_client', return_value=mock_cloudwatch):
        result = evaluate_group_application_match('USER', 'john.doe', 'SomeApp')
        
        assert result == ''
        assert not mock_cloudwatch.put_metric_data.called, \
            "Should not emit metrics for USER principals"


def test_metrics_emitted_for_edge_cases():
    """
    Test that metrics are emitted for edge cases (None, empty strings).
    Validates: Task 7 - CloudWatch metrics emission
    """
    test_cases = [
        (None, 'SomeApp'),
        ('SomeGroup', None),
        ('', 'SomeApp'),
        ('SomeGroup', ''),
        ('   ', 'SomeApp'),
    ]
    
    
    for principal_name, app_name in test_cases:
        # Create mock CloudWatch client
        mock_cloudwatch = MagicMock()
        
        # Patch the _get_cloudwatch_client function to return our mock
        with patch.object(matching, '_get_cloudwatch_client', return_value=mock_cloudwatch):
            result = evaluate_group_application_match('GROUP', principal_name, app_name)
            
            assert result == 'No', f"Expected 'No' for edge case: principal={principal_name}, app={app_name}"
            assert mock_cloudwatch.put_metric_data.called, \
                f"Expected metrics to be emitted for edge case: principal={principal_name}, app={app_name}"
            
            # Verify the metric data
            call_args = mock_cloudwatch.put_metric_data.call_args
            metric_data = call_args[1]['MetricData']
            metric_names = [m['MetricName'] for m in metric_data]
            
            assert 'MatchingEvaluations' in metric_names
            assert 'MatchedNo' in metric_names


def test_metrics_emission_failure_does_not_break_matching():
    """
    Test that metrics emission failures don't break the matching logic.
    Validates: Task 7 - CloudWatch metrics emission
    """
    
    # Create mock CloudWatch client that raises an exception
    mock_cloudwatch = MagicMock()
    mock_cloudwatch.put_metric_data.side_effect = Exception("CloudWatch error")
    
    # Patch both the CloudWatch client and logger
    with patch.object(matching, '_get_cloudwatch_client', return_value=mock_cloudwatch), \
         patch.object(matching, 'logger') as mock_logger:
        result = evaluate_group_application_match('GROUP', 'Engineering', 'Engineering-Portal')
        
        # Matching should still work despite metrics failure
        assert result == 'Yes', "Matching should work even if metrics emission fails"
        
        # Verify warning was logged
        assert mock_logger.warning.called, "Expected warning to be logged for metrics failure"


# ============================================================================
# Symmetric whole-word matching behavior table
# Raw SCIM group names commonly look like "AppName-Role" (longer than the
# application name). Symmetric matching (either side's tokens form a
# contiguous whole-token run within the other) recognizes these without a
# regex, while still rejecting fragment/prefix matches.
# ============================================================================

def test_symmetric_app_word_is_whole_token_of_group():
    """app 'CustomerPortal' vs group 'CustomerPortal-Admins' -> 'Yes' (app word is whole token of group)."""
    result = evaluate_group_application_match('GROUP', 'CustomerPortal-Admins', 'CustomerPortal')
    assert result == 'Yes', f"Expected 'Yes', got '{result}'"


def test_symmetric_app_word_is_whole_token_of_group_finance():
    """app 'Finance' vs group 'Finance-ReadOnly' -> 'Yes'."""
    result = evaluate_group_application_match('GROUP', 'Finance-ReadOnly', 'Finance')
    assert result == 'Yes', f"Expected 'Yes', got '{result}'"


def test_symmetric_app_word_interior_token_of_group():
    """app 'CustomerPortal' vs group 'Okta-CustomerPortal-Prod' -> 'Yes'."""
    result = evaluate_group_application_match('GROUP', 'Okta-CustomerPortal-Prod', 'CustomerPortal')
    assert result == 'Yes', f"Expected 'Yes', got '{result}'"


def test_symmetric_exact_match():
    """app 'CustomerPortal' vs group 'CustomerPortal' -> 'Yes'."""
    result = evaluate_group_application_match('GROUP', 'CustomerPortal', 'CustomerPortal')
    assert result == 'Yes', f"Expected 'Yes', got '{result}'"


def test_symmetric_original_direction_still_works():
    """app 'MyApp-Developers' vs group 'Developers' -> 'Yes' (group inside app, original direction)."""
    result = evaluate_group_application_match('GROUP', 'Developers', 'MyApp-Developers')
    assert result == 'Yes', f"Expected 'Yes', got '{result}'"


def test_symmetric_multitoken_contiguous_run_either_direction():
    """app 'Customer-Portal' vs group 'Customer-Portal-Admins' -> 'Yes' (multi-token contiguous run)."""
    result = evaluate_group_application_match('GROUP', 'Customer-Portal-Admins', 'Customer-Portal')
    assert result == 'Yes', f"Expected 'Yes', got '{result}'"


def test_symmetric_fragment_not_whole_token_is_no():
    """app 'CustomerPortal' vs group 'Portal' -> 'No' (fragment, not a whole token)."""
    result = evaluate_group_application_match('GROUP', 'Portal', 'CustomerPortal')
    assert result == 'No', f"Expected 'No', got '{result}'"


def test_symmetric_prefix_only_fail_open_stays_closed():
    """app 'CustomerPortal' vs group 'C' -> 'No' (prefix-only fail-open stays closed)."""
    result = evaluate_group_application_match('GROUP', 'C', 'CustomerPortal')
    assert result == 'No', f"Expected 'No', got '{result}'"


def test_symmetric_no_regex_multiword_group_is_no():
    """app 'CustomerPortal' vs group 'AWS-C-Admins' -> 'No'."""
    result = evaluate_group_application_match('GROUP', 'AWS-C-Admins', 'CustomerPortal')
    assert result == 'No', f"Expected 'No', got '{result}'"


def test_symmetric_wrong_app_is_no():
    """app 'CustomerPortal' vs group 'AWS-Billing-Admins' -> 'No' (wrong app)."""
    result = evaluate_group_application_match('GROUP', 'AWS-Billing-Admins', 'CustomerPortal')
    assert result == 'No', f"Expected 'No', got '{result}'"


def test_symmetric_app_fragment_of_group_is_no():
    """app 'Portal' vs group 'CustomerPortal-Admins' -> 'No' ('Portal' is not a whole token of 'customerportal')."""
    result = evaluate_group_application_match('GROUP', 'CustomerPortal-Admins', 'Portal')
    assert result == 'No', f"Expected 'No', got '{result}'"


def test_correct_metric_values():
    """
    Test that metrics have correct values and units.
    Validates: Task 7 - CloudWatch metrics emission
    """
    
    # Create mock CloudWatch client
    mock_cloudwatch = MagicMock()
    
    # Patch the _get_cloudwatch_client function to return our mock
    with patch.object(matching, '_get_cloudwatch_client', return_value=mock_cloudwatch):
        result = evaluate_group_application_match('GROUP', 'Engineering', 'Engineering-Portal')
        
        assert result == 'Yes'
        
        # Verify the metric data structure
        call_args = mock_cloudwatch.put_metric_data.call_args
        metric_data = call_args[1]['MetricData']
        
        for metric in metric_data:
            assert 'MetricName' in metric, "Metric should have MetricName"
            assert 'Value' in metric, "Metric should have Value"
            assert 'Unit' in metric, "Metric should have Unit"
            assert metric['Value'] == 1, "Metric value should be 1 for counter"
            assert metric['Unit'] == 'Count', "Metric unit should be Count"
