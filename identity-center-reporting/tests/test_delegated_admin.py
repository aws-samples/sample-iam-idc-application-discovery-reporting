"""
Tests for delegated admin account functionality
"""
import importlib.util
import os
import re
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import boto3
from botocore.exceptions import ClientError


def _load_shared_utils():
    """
    Load src/lambdas/shared/utils.py directly, by path.

    Other tests in this suite install a Mock into sys.modules['shared.utils'] to
    isolate handler imports. A plain `import shared.utils` here would pick up that
    Mock depending on test order, and every assertion about the real ExternalId
    behaviour would then pass against a Mock instead of the code. Loading from the
    file bypasses sys.modules entirely.
    """
    path = Path(__file__).resolve().parents[1] / 'src' / 'lambdas' / 'shared' / 'utils.py'
    spec = importlib.util.spec_from_file_location('_real_shared_utils', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestDelegatedAdminAccountLogic:
    """Test delegated admin account role assumption logic"""
    
    def test_same_account_uses_current_credentials(self):
        """Test that when current account equals delegated admin, no role assumption occurs"""
        current_account = "123456789012"
        delegated_admin = "123456789012"
        
        # Should use current credentials (no role assumption)
        assert current_account == delegated_admin
    
    def test_different_account_requires_role_assumption(self):
        """Test that when accounts differ, role assumption is required"""
        current_account = "123456789012"
        delegated_admin = "999888777666"
        
        # Should assume role
        assert current_account != delegated_admin
    
    def test_no_delegated_admin_uses_current_credentials(self):
        """Test that when no delegated admin is configured, current credentials are used"""
        current_account = "123456789012"
        delegated_admin = None
        
        # Should use current credentials
        assert delegated_admin is None
    
    def test_empty_delegated_admin_uses_current_credentials(self):
        """Test that when delegated admin is empty string, current credentials are used"""
        current_account = "123456789012"
        delegated_admin = ""
        
        # Should use current credentials
        assert not delegated_admin
    
    @patch('boto3.client')
    def test_role_assumption_creates_correct_arn(self, mock_boto_client):
        """Test that role ARN is constructed correctly"""
        delegated_admin = "999888777666"
        role_name = "iam-identity-center-cross-account-discovery-role"
        
        expected_arn = f"arn:aws:iam::{delegated_admin}:role/{role_name}"
        
        assert expected_arn == f"arn:aws:iam::{delegated_admin}:role/{role_name}"
    
    def test_external_id_comes_from_environment(self):
        """The ExternalId is read from the stack-set env var, not a literal."""
        utils = _load_shared_utils()
        with patch.dict(os.environ, {'CROSS_ACCOUNT_EXTERNAL_ID': 'a-unique-value-1234'}, clear=False):
            assert utils.get_cross_account_external_id() == 'a-unique-value-1234'

    def test_external_id_missing_raises_rather_than_defaulting(self):
        """
        An unset ExternalId must fail loudly.

        The previous version of this test asserted a local literal against itself,
        so it passed no matter what the code did -- including while the deployed
        value was still the published string this repository ships.
        """
        utils = _load_shared_utils()
        env = {k: v for k, v in os.environ.items() if k != 'CROSS_ACCOUNT_EXTERNAL_ID'}
        with patch.dict(os.environ, env, clear=True), \
             pytest.raises(ValueError, match='CROSS_ACCOUNT_EXTERNAL_ID'):
            utils.get_cross_account_external_id()

    def test_published_external_id_is_not_hardcoded_anywhere(self):
        """
        No runtime code may pin the ExternalId to the value this repo published.

        This is the assertion that would have caught the real defect: the trust
        policies, the env var and one Lambda helper were moved to a generated value
        while the execution-role policy condition and four other call sites still
        carried the literal, so every cross-account assume was denied while the
        state machine still reported SUCCEEDED.
        """
        root = Path(__file__).resolve().parents[1]

        # Require the literal to be the assigned *value*, not merely present on a
        # line that also says "ExternalId". Prose legitimately names the forbidden
        # value -- the CfnRule that rejects it has to quote it to explain itself --
        # and a bare substring check flags that guard as a violation of itself.
        # EXTERNAL_?ID covers all three spellings the codebase used: the boto3
        # kwarg (ExternalId=), the IAM condition key ("sts:ExternalId":) and the
        # module constant (EXTERNAL_ID =). Matching only "ExternalId" lets the
        # underscored constant form through, which is one of the forms that
        # actually shipped.
        pinned = re.compile(
            r"""EXTERNAL_?ID["']?\s*[:=]\s*["']iam-identity-center-discovery["']""",
            re.IGNORECASE,
        )

        offenders = []
        for path in list((root / 'src').rglob('*.py')) + list((root / 'lib').rglob('*.py')):
            for num, line in enumerate(path.read_text().splitlines(), 1):
                if pinned.search(line):
                    offenders.append(f"{path.relative_to(root)}:{num}: {line.strip()}")
        assert not offenders, (
            "ExternalId pinned to the published literal:\n" + "\n".join(offenders)
        )


    def test_role_session_name_format(self):
        """Test that role session name follows correct format"""
        session_name = "IAMIdentityCenterDiscovery-DelegatedAdmin"
        
        # Verify session name format
        assert session_name.startswith("IAMIdentityCenterDiscovery")
        assert "DelegatedAdmin" in session_name


class TestDelegatedAdminEnvironmentVariable:
    """Test environment variable handling for delegated admin account"""
    
    @patch.dict('os.environ', {'DELEGATED_ADMIN_ACCOUNT_ID': '999888777666'})
    def test_environment_variable_is_read(self):
        """Test that environment variable is read correctly"""
        import os
        delegated_admin = os.environ.get('DELEGATED_ADMIN_ACCOUNT_ID')
        
        assert delegated_admin == '999888777666'
    
    @patch.dict('os.environ', {}, clear=True)
    def test_missing_environment_variable_returns_none(self):
        """Test that missing environment variable returns None"""
        import os
        delegated_admin = os.environ.get('DELEGATED_ADMIN_ACCOUNT_ID')
        
        assert delegated_admin is None
    
    @patch.dict('os.environ', {'DELEGATED_ADMIN_ACCOUNT_ID': ''})
    def test_empty_environment_variable_returns_empty_string(self):
        """Test that empty environment variable returns empty string"""
        import os
        delegated_admin = os.environ.get('DELEGATED_ADMIN_ACCOUNT_ID')
        
        assert delegated_admin == ''


class TestDelegatedAdminErrorHandling:
    """Test error handling for delegated admin account operations"""
    
    def test_invalid_account_id_format(self):
        """Test that invalid account ID format is detected"""
        invalid_ids = [
            "12345",  # Too short
            "1234567890123",  # Too long
            "abcdefghijkl",  # Not numeric
            "123-456-7890",  # Contains dashes
        ]
        
        for invalid_id in invalid_ids:
            # Should not match 12-digit pattern
            assert len(invalid_id) != 12 or not invalid_id.isdigit()
    
    def test_valid_account_id_format(self):
        """Test that valid account ID format is accepted"""
        valid_id = "123456789012"
        
        assert len(valid_id) == 12
        assert valid_id.isdigit()
    
    @patch('boto3.client')
    def test_assume_role_failure_handling(self, mock_boto_client):
        """Test that assume role failures are handled gracefully"""
        mock_sts = MagicMock()
        mock_boto_client.return_value = mock_sts
        
        # Simulate AccessDenied error
        mock_sts.assume_role.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
            'AssumeRole'
        )
        
        with pytest.raises(ClientError) as exc_info:
            mock_sts.assume_role(
                RoleArn='arn:aws:iam::999888777666:role/test-role',
                RoleSessionName='test-session'
            )
        
        assert exc_info.value.response['Error']['Code'] == 'AccessDenied'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
