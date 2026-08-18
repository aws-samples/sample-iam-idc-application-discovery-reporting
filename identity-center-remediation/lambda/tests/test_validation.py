"""
Property-based tests for validation logic module.

Feature: identity-center-app-monitor
"""

import pytest
from hypothesis import given, strategies as st, assume
from validation import validate_assignment, ValidationResult, _tokenize, run_in
from remediation import should_trigger_remediation, get_remediation_action


# **Feature: identity-center-app-monitor, Property 2: Whole-word (token) validation**
# **Validates: Requirements 2.3**
# NOTE: This property previously asserted raw substring equivalence
# (`group_name.lower() in application_name.lower()`), which encoded the fail-open
# bug where a short extracted value (e.g. "C") wrongly matched a longer application
# word (e.g. "CustomerPortal"). It has been corrected to compute the expected
# result from the symmetric whole-word (token) rule instead.
@given(
    application_name=st.text(min_size=1, max_size=200),
    group_name=st.text(min_size=1, max_size=100)
)
def test_property_whole_word_token_validation(application_name, group_name):
    """
    Property 2: Whole-word (token) validation

    For any application name and group name pair, the validation function should
    return true if and only if either side's tokens (split on '-', '_', and
    whitespace, lowercased) appear as a contiguous run of whole tokens within the
    other side's tokens.

    Validates: Requirements 2.3
    """
    # Perform validation
    result = validate_assignment(application_name, group_name)

    # Check if either side's tokens are a contiguous run of whole tokens within
    # the other side's tokens (symmetric match)
    app_tokens = _tokenize(application_name)
    group_tokens = _tokenize(group_name)
    expected_compliant = run_in(app_tokens, group_tokens) or run_in(group_tokens, app_tokens)

    # Verify the result matches expected compliance
    assert result.is_compliant == expected_compliant, (
        f"Expected is_compliant={expected_compliant} for "
        f"app='{application_name}', group='{group_name}', "
        f"but got {result.is_compliant}"
    )

    # Verify result structure
    assert isinstance(result, ValidationResult)
    assert result.application_name == application_name
    assert result.group_name == group_name
    assert isinstance(result.reason, str)
    assert len(result.reason) > 0


def test_validation_exact_match():
    """Test that exact matches are compliant."""
    result = validate_assignment("MyApp", "MyApp")
    assert result.is_compliant is True


def test_validation_whole_word_match():
    """Test that a whole-word (token) match is compliant."""
    result = validate_assignment("MyApp-Developers", "Developers")
    assert result.is_compliant is True


def test_validation_case_insensitive():
    """Test that matching is case-insensitive."""
    result = validate_assignment("MyApp-DEVS", "devs")
    assert result.is_compliant is True
    
    result = validate_assignment("myapp-devs", "DEVS")
    assert result.is_compliant is True


def test_validation_no_match():
    """Test that non-matching names are non-compliant."""
    result = validate_assignment("MyApp", "OtherGroup")
    assert result.is_compliant is False


def test_validation_empty_application_name():
    """Test that empty application name is non-compliant."""
    result = validate_assignment("", "GroupName")
    assert result.is_compliant is False
    assert "empty" in result.reason.lower()


def test_validation_empty_group_name():
    """Test that empty group name is non-compliant."""
    result = validate_assignment("AppName", "")
    assert result.is_compliant is False
    assert "empty" in result.reason.lower()


def test_validation_special_characters():
    """Test that special characters are handled correctly."""
    result = validate_assignment("MyApp-Dev@2024", "Dev@2024")
    assert result.is_compliant is True
    
    result = validate_assignment("App_Name-123", "Name-123")
    assert result.is_compliant is True


def test_validation_unicode_characters():
    """Test that Unicode characters are handled correctly."""
    result = validate_assignment("MyApp-Développeurs", "Développeurs")
    assert result.is_compliant is True
    
    result = validate_assignment("应用程序-开发者", "开发者")
    assert result.is_compliant is True


def test_validation_whitespace():
    """Test that whitespace is preserved in matching."""
    result = validate_assignment("My App Name", "App Name")
    assert result.is_compliant is True
    
    result = validate_assignment("MyAppName", "App Name")
    assert result.is_compliant is False


def test_validation_result_to_dict():
    """Test that ValidationResult can be converted to dictionary."""
    result = validate_assignment("MyApp", "App")
    result_dict = result.to_dict()
    
    assert isinstance(result_dict, dict)
    assert 'is_compliant' in result_dict
    assert 'application_name' in result_dict
    assert 'group_name' in result_dict
    assert 'reason' in result_dict


# **Feature: identity-center-app-monitor, Property 3: Non-compliant assignments trigger remediation**
# **Validates: Requirements 2.5**
@given(
    application_name=st.text(min_size=1, max_size=200),
    group_name=st.text(min_size=1, max_size=100)
)
def test_property_non_compliant_triggers_remediation(application_name, group_name):
    """
    Property 3: Non-compliant assignments trigger remediation
    
    For any non-compliant assignment (where group name is not in application name),
    the system should invoke the remediation logic path.
    
    Validates: Requirements 2.5
    """
    # Perform validation
    result = validate_assignment(application_name, group_name)
    
    # Check if remediation should be triggered
    should_remediate = should_trigger_remediation(result)
    
    # Verify remediation is triggered if and only if assignment is non-compliant
    expected_remediation = not result.is_compliant
    assert should_remediate == expected_remediation, (
        f"Expected remediation={expected_remediation} for "
        f"app='{application_name}', group='{group_name}', "
        f"is_compliant={result.is_compliant}, "
        f"but got should_remediate={should_remediate}"
    )


# **Feature: identity-center-app-monitor, Property 4: Configuration determines remediation action**
# **Validates: Requirements 3.5**
@given(
    application_name=st.text(min_size=1, max_size=200),
    group_name=st.text(min_size=1, max_size=100),
    enable_auto_deletion=st.booleans()
)
def test_property_configuration_determines_remediation_action(
    application_name, group_name, enable_auto_deletion
):
    """
    Property 4: Configuration determines remediation action
    
    For any non-compliant assignment, when the EnableAutoDeletion flag is true,
    the system should invoke the delete API; when false, the system should only
    send notifications.
    
    Validates: Requirements 3.5
    """
    # Perform validation
    result = validate_assignment(application_name, group_name)
    
    # Get remediation action based on configuration
    action = get_remediation_action(result, enable_auto_deletion)
    
    # Verify action is correct based on compliance and configuration
    if result.is_compliant:
        # Compliant assignments should have no remediation action
        assert action == 'NONE', (
            f"Expected action='NONE' for compliant assignment, "
            f"but got action='{action}'"
        )
    else:
        # Non-compliant assignments should have action based on configuration
        if enable_auto_deletion:
            assert action == 'DELETED', (
                f"Expected action='DELETED' when enable_auto_deletion=True, "
                f"but got action='{action}'"
            )
        else:
            assert action == 'NOTIFICATION_ONLY', (
                f"Expected action='NOTIFICATION_ONLY' when enable_auto_deletion=False, "
                f"but got action='{action}'"
            )



# **Tests for regex-based group name extraction**

def test_validation_with_regex_prefix_extraction():
    """Test regex extraction of prefix before first dash from the group name."""
    regex = r"^([^-]+)"

    # Group: MyApp-Dev, extract: MyApp, Application: MyApp-Production
    result = validate_assignment("MyApp-Production", "MyApp-Dev", regex)
    assert result.is_compliant is True
    assert "MyApp" in result.reason

    # Group: ProdApp-Something, extract: ProdApp, Application: ProdApp
    result = validate_assignment("ProdApp", "ProdApp-Something", regex)
    assert result.is_compliant is True


def test_validation_with_regex_suffix_extraction():
    """Test regex extraction of suffix after last dash from the group name."""
    regex = r"([^-]+)$"

    # Group: Team-Dev, extract: Dev, Application: MyApp-Dev
    result = validate_assignment("MyApp-Dev", "Team-Dev", regex)
    assert result.is_compliant is True

    # Group: Team-Prod, extract: Prod, Application: MyApp-Prod
    result = validate_assignment("MyApp-Prod", "Team-Prod", regex)
    assert result.is_compliant is True


def test_validation_with_regex_middle_segment():
    """Test regex extraction of a middle segment from the group name."""
    regex = r"^[^-]+-([^-]+)"

    # Group: AWS-Developers-Team, extract: Developers, Application: App-Developers
    result = validate_assignment("App-Developers", "AWS-Developers-Team", regex)
    assert result.is_compliant is True

    # Group: AWS-Operations-Group, extract: Operations, Application: Ops-Operations
    result = validate_assignment("Ops-Operations", "AWS-Operations-Group", regex)
    assert result.is_compliant is True


def test_validation_with_regex_brackets():
    """Test regex extraction of text between brackets from the group name."""
    regex = r"\[([^\]]+)\]"

    # Group: Team [Dev] Group, extract: Dev, Application: MyApp-Dev
    result = validate_assignment("MyApp-Dev", "Team [Dev] Group", regex)
    assert result.is_compliant is True

    # Group: Team [Prod] Group, extract: Prod, Application: System-Prod
    result = validate_assignment("System-Prod", "Team [Prod] Group", regex)
    assert result.is_compliant is True


def test_validation_with_regex_environment_code():
    """Test regex extraction of an environment keyword from the group name."""
    regex = r"(?i)(dev|prod|test|staging|qa)"  # Case-insensitive flag

    # Group: Team-Dev-Users, extract: Dev, Application: MyApp-Dev-System
    result = validate_assignment("MyApp-Dev-System", "Team-Dev-Users", regex)
    assert result.is_compliant is True

    # Group: Team-Prod-Users, extract: Prod, Application: MyApp-Prod-Environment
    result = validate_assignment("MyApp-Prod-Environment", "Team-Prod-Users", regex)
    assert result.is_compliant is True


def test_validation_with_regex_case_insensitive():
    """Test that regex extraction + matching is case-insensitive."""
    regex = r"^([^-]+)"

    # Group: MYAPP-DEV, extract: MYAPP, Application: myapp-production (case-insensitive)
    result = validate_assignment("myapp-production", "MYAPP-DEV", regex)
    assert result.is_compliant is True
    
    # Group: ProdApp-Something, extract: ProdApp, Application: prodapp-system (case-insensitive)
    result = validate_assignment("prodapp-system", "ProdApp-Something", regex)
    assert result.is_compliant is True


def test_validation_with_regex_no_match():
    """Test that non-matching regex extractions are non-compliant."""
    regex = r"^([^-]+)"

    # Group: DevTeam-Users, extract: DevTeam, Application: MyApp-Prod (not found)
    result = validate_assignment("MyApp-Prod", "DevTeam-Users", regex)
    assert result.is_compliant is False
    assert "DevTeam" in result.reason


def test_validation_with_regex_no_capture_group():
    """Test that regex without capture group falls back to full name."""
    regex = r"^[^-]+"  # No capture group
    
    # Should fall back to full group name matching
    result = validate_assignment("MyApp-Dev-Team-AWS", "Dev-Team-AWS", regex)
    assert result.is_compliant is True


def test_validation_with_regex_no_match_pattern():
    """Test that regex that doesn't match falls back to full name."""
    regex = r"\[([^\]]+)\]"  # Looks for brackets
    
    # Group has no brackets, should use full name
    result = validate_assignment("MyApp-Developers", "Developers", regex)
    assert result.is_compliant is True


def test_validation_with_invalid_regex():
    """Test that invalid regex falls back to full name matching."""
    regex = r"[invalid(regex"  # Invalid regex
    
    # Should fall back to full group name matching
    result = validate_assignment("MyApp-Developers", "Developers", regex)
    assert result.is_compliant is True


def test_validation_with_empty_regex():
    """Test that empty regex uses default whole-word matching."""
    # Empty string should be treated as no regex
    result = validate_assignment("MyApp-Developers", "Developers", "")
    assert result.is_compliant is True
    
    # None should also use default matching
    result = validate_assignment("MyApp-Developers", "Developers", None)
    assert result.is_compliant is True


def test_validation_regex_reason_includes_extraction():
    """Test that validation reason includes the extracted friendly group name."""
    regex = r"^([^-]+)"

    # Group: MyApp-Dev-System, extract: MyApp, Application: MyApp-Production
    result = validate_assignment("MyApp-Production", "MyApp-Dev-System", regex)
    assert result.is_compliant is True
    assert "MyApp" in result.reason
    assert "extracted from" in result.reason.lower()
    assert "MyApp-Dev-System" in result.reason


# **Regression tests: whole-word (token) matching**
# **Validates: Requirements 1.1-1.6, 3.1-3.4, 7.1-7.5**

def test_whole_word_match_first_position():
    """Group token matches the first token of the application name."""
    result = validate_assignment("Finance-Prod-System", "Finance")
    assert result.is_compliant is True


def test_whole_word_match_middle_position():
    """Group token matches a middle token of the application name."""
    result = validate_assignment("AWS-Finance-System", "Finance")
    assert result.is_compliant is True


def test_whole_word_match_last_position():
    """Group token matches the last token of the application name."""
    result = validate_assignment("System-AWS-Finance", "Finance")
    assert result.is_compliant is True


def test_fail_open_probe_single_char_extraction():
    """AWS-C-Admins extracts 'C', which must NOT match CustomerPortal (regression for the fail-open bug)."""
    regex = r"^[^-]+-([^-]+)-"
    result = validate_assignment("CustomerPortal", "AWS-C-Admins", regex)
    assert result.is_compliant is False


def test_fail_open_probe_short_prefix_extraction():
    """AWS-Cust-Admins extracts 'Cust', which must NOT match CustomerPortal as a prefix."""
    regex = r"^[^-]+-([^-]+)-"
    result = validate_assignment("CustomerPortal", "AWS-Cust-Admins", regex)
    assert result.is_compliant is False


def test_fail_open_probe_no_regex_multiword_group():
    """AWS-Customer-Billing-Admins (no regex) must NOT match CustomerPortal: no contiguous run of whole app tokens."""
    result = validate_assignment("CustomerPortal", "AWS-Customer-Billing-Admins")
    assert result.is_compliant is False


def test_fail_open_probe_prod_prefix_extraction():
    """AWS-Prod-Admins extracts 'Prod', which must NOT match ProdPortal as a prefix."""
    regex = r"^[^-]+-([^-]+)-"
    result = validate_assignment("ProdPortal", "AWS-Prod-Admins", regex)
    assert result.is_compliant is False


def test_decorated_app_any_position_match_with_regex():
    """Group AWS-CustomerPortal-Admins extracts CustomerPortal via regex and matches
    application prod-customerportal-web-01 at a middle token position."""
    regex = r"^[^-]+-([^-]+)-"
    result = validate_assignment("prod-customerportal-web-01", "AWS-CustomerPortal-Admins", regex)
    assert result.is_compliant is True


def test_underscore_delimited_variant_no_regex():
    """Underscore-delimited group and application names are tokenized and matched (no-regex fallback path)."""
    result = validate_assignment("prod_customerportal_web", "customerportal")
    assert result.is_compliant is True


def test_underscore_delimited_variant_with_regex():
    """Underscore-delimited names are tokenized and matched via the regex-extraction path."""
    regex = r"^([^_]+)"
    result = validate_assignment("prod_customerportal_web", "customerportal_admins", regex)
    assert result.is_compliant is True


def test_multiword_contiguous_match():
    """Multi-token group value 'Customer-Portal' matches as a contiguous run within 'Customer-Portal-Prod'."""
    result = validate_assignment("Customer-Portal-Prod", "Customer-Portal")
    assert result.is_compliant is True


def test_multiword_contiguous_match_not_adjacent_fails():
    """Multi-token group value tokens that are NOT contiguous in the application name are non-compliant."""
    result = validate_assignment("Customer-Prod-Portal", "Customer-Portal")
    assert result.is_compliant is False


def test_no_regex_fallback_whole_word_semantics():
    """The no-regex fallback path (full group name) uses whole-word semantics, not substring."""
    # 'admin' is a substring of 'administrator' but not a whole token of it.
    result = validate_assignment("administrator-portal", "admin")
    assert result.is_compliant is False

    # 'admin' as a whole token in the application name is compliant.
    result = validate_assignment("admin-portal", "admin")
    assert result.is_compliant is True


# **Symmetric whole-word matching behavior table**
# **Validates: Requirements 4.1-4.11**
# Raw SCIM group names commonly look like "AppName-Role" (longer than the
# application name). Symmetric matching (either side's tokens form a
# contiguous whole-token run within the other) recognizes these without a
# regex, while still rejecting fragment/prefix matches.

def test_symmetric_app_word_is_whole_token_of_group():
    """app 'CustomerPortal' vs group 'CustomerPortal-Admins' -> compliant (app word is whole token of group)."""
    result = validate_assignment("CustomerPortal", "CustomerPortal-Admins")
    assert result.is_compliant is True


def test_symmetric_app_word_is_whole_token_of_group_finance():
    """app 'Finance' vs group 'Finance-ReadOnly' -> compliant."""
    result = validate_assignment("Finance", "Finance-ReadOnly")
    assert result.is_compliant is True


def test_symmetric_app_word_interior_token_of_group():
    """app 'CustomerPortal' vs group 'Okta-CustomerPortal-Prod' -> compliant."""
    result = validate_assignment("CustomerPortal", "Okta-CustomerPortal-Prod")
    assert result.is_compliant is True


def test_symmetric_exact_match():
    """app 'CustomerPortal' vs group 'CustomerPortal' -> compliant."""
    result = validate_assignment("CustomerPortal", "CustomerPortal")
    assert result.is_compliant is True


def test_symmetric_original_direction_still_works():
    """app 'MyApp-Developers' vs group 'Developers' -> compliant (group inside app, original direction)."""
    result = validate_assignment("MyApp-Developers", "Developers")
    assert result.is_compliant is True


def test_symmetric_multitoken_contiguous_run_either_direction():
    """app 'Customer-Portal' vs group 'Customer-Portal-Admins' -> compliant (multi-token contiguous run)."""
    result = validate_assignment("Customer-Portal", "Customer-Portal-Admins")
    assert result.is_compliant is True


def test_symmetric_fragment_not_whole_token_is_flagged():
    """app 'CustomerPortal' vs group 'Portal' -> flagged (fragment, not a whole token)."""
    result = validate_assignment("CustomerPortal", "Portal")
    assert result.is_compliant is False


def test_symmetric_prefix_only_fail_open_stays_closed():
    """app 'CustomerPortal' vs group 'C' -> flagged (prefix-only fail-open stays closed)."""
    result = validate_assignment("CustomerPortal", "C")
    assert result.is_compliant is False


def test_symmetric_no_regex_multiword_group_flagged():
    """app 'CustomerPortal' vs group 'AWS-C-Admins' -> flagged."""
    result = validate_assignment("CustomerPortal", "AWS-C-Admins")
    assert result.is_compliant is False


def test_symmetric_wrong_app_flagged():
    """app 'CustomerPortal' vs group 'AWS-Billing-Admins' -> flagged (wrong app)."""
    result = validate_assignment("CustomerPortal", "AWS-Billing-Admins")
    assert result.is_compliant is False


def test_symmetric_app_fragment_of_group_flagged():
    """app 'Portal' vs group 'CustomerPortal-Admins' -> flagged ('Portal' is not a whole token of 'customerportal')."""
    result = validate_assignment("Portal", "CustomerPortal-Admins")
    assert result.is_compliant is False
