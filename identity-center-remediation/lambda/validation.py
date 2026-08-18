"""
Validation logic module for Identity Center application assignments.

This module validates that a group's friendly value and the application name
match by symmetric, case-insensitive, delimiter-based whole-word (token)
matching: compliant when either side's tokens appear as a contiguous run of
whole tokens within the other side's tokens.
"""

import re
from typing import Any

_DELIMITERS = re.compile(r"[-_\s]+")


def _tokenize(value: str) -> list[str]:
    """Split on '-', '_', and whitespace only; drop empty parts; lowercase.

    Does NOT split camelCase or digit boundaries: 'CustomerPortal' -> ['customerportal'].
    """
    return [part.lower() for part in _DELIMITERS.split(value) if part]


def run_in(needle_tokens: list[str], hay_tokens: list[str]) -> bool:
    """True if needle_tokens appear as a contiguous run of whole tokens in hay_tokens."""
    if not needle_tokens or len(needle_tokens) > len(hay_tokens):
        return False
    last = len(hay_tokens) - len(needle_tokens)
    for start in range(last + 1):
        if hay_tokens[start:start + len(needle_tokens)] == needle_tokens:
            return True
    return False


class ValidationResult:
    """Structured result of a validation check."""

    def __init__(self, is_compliant: bool, application_name: str, group_name: str, reason: str = ""):
        self.is_compliant = is_compliant
        self.application_name = application_name
        self.group_name = group_name
        self.reason = reason

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            'is_compliant': self.is_compliant,
            'application_name': self.application_name,
            'group_name': self.group_name,
            'reason': self.reason
        }

    def __repr__(self) -> str:
        return f"ValidationResult(is_compliant={self.is_compliant}, reason='{self.reason}')"


def validate_assignment(application_name: str, group_name: str, group_name_regex: str = None) -> ValidationResult:
    """
    Validate that a group's friendly value and an application name match by
    symmetric whole-word (token) matching.

    Tokenizes both the application name and the extracted friendly group value on
    delimiters ('-', '_', whitespace) and checks whether either side's tokens
    appear as a contiguous run of whole tokens anywhere within the other side's
    token list. A single-token side must equal a whole token on the other side —
    never a substring or prefix of one. This lets a raw group name like
    "CustomerPortal-Admins" match application "CustomerPortal" with no regex,
    while still rejecting fragment/prefix matches. If a regex pattern is
    provided, it extracts a friendly name from the group name before matching
    (for example, extracting "Finance" from "AWS-Finance-Admins").

    Args:
        application_name: Name of the Identity Center application
        group_name: Name of the Identity Center group
        group_name_regex: Optional regex pattern to extract a friendly group name
                         from the full group name. The first capture group is used
                         as the friendly name.

    Returns:
        ValidationResult with compliance status and details

    Examples:
        >>> validate_assignment("MyApp-Developers", "Developers").is_compliant
        True
        >>> validate_assignment("MyApp", "OtherGroup").is_compliant
        False
        >>> validate_assignment("MyApp-DEVS", "devs").is_compliant
        True
        >>> validate_assignment("Finance_PROD", "AWS-Finance-Admins", "AWS-([^-]+)-").is_compliant
        True
        >>> validate_assignment("CustomerPortal", "AWS-C-Admins", "AWS-([^-]+)-").is_compliant
        False
        >>> validate_assignment("CustomerPortal", "CustomerPortal-Admins").is_compliant
        True
    """
    # Handle edge cases: empty strings
    if not application_name or not group_name:
        return ValidationResult(
            is_compliant=False,
            application_name=application_name,
            group_name=group_name,
            reason="Application name or group name is empty"
        )

    # Extract a friendly name from the group name if a regex is provided
    friendly_group_name = group_name
    if group_name_regex:
        try:
            match = re.search(group_name_regex, group_name)
            extracted = match.group(1) if (match and match.groups()) else None
            # group(1) is None when the first group is optional and did not
            # participate (e.g. '^(ADFS-)?([^-]+)' against a name with no
            # prefix), and '' when it matched zero characters (e.g. '^([A-Z]*)'
            # against a lowercase name). Both are unusable as a needle: None
            # raises on .lower(), and an empty needle would make the comparison
            # meaningless. Fall back to the full group name so the verdict is
            # still computed against something the operator actually named.
            if extracted and extracted.strip():
                friendly_group_name = extracted
            else:
                friendly_group_name = group_name
        except Exception:
            # If the regex itself is invalid, fall back to the full group name.
            friendly_group_name = group_name

    # Perform case-insensitive symmetric whole-word (token) matching
    app_tokens = _tokenize(application_name)
    group_tokens = _tokenize(friendly_group_name)

    is_compliant = run_in(app_tokens, group_tokens) or run_in(group_tokens, app_tokens)

    if is_compliant:
        if friendly_group_name != group_name:
            reason = f"Friendly group name '{friendly_group_name}' (extracted from '{group_name}') shares a whole word with application name '{application_name}'"
        else:
            reason = f"Group name '{group_name}' shares a whole word with application name '{application_name}'"
    else:
        if friendly_group_name != group_name:
            reason = f"Friendly group name '{friendly_group_name}' (extracted from '{group_name}') shares no whole word with application name '{application_name}'"
        else:
            reason = f"Group name '{group_name}' shares no whole word with application name '{application_name}'"

    return ValidationResult(
        is_compliant=is_compliant,
        application_name=application_name,
        group_name=group_name,
        reason=reason
    )
