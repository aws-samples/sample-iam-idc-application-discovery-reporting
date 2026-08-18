"""
Property-based tests for retry logic with exponential backoff.

**Feature: identity-center-app-monitor, Property 7: SNS retry with exponential backoff**
**Feature: identity-center-app-monitor, Property 11: API retry with exponential backoff**
**Validates: Requirements 4.4, 9.1**
"""

import pytest
from hypothesis import given, strategies as st, settings
from botocore.exceptions import ClientError
from retry import (
    retry_with_backoff,
    calculate_backoff_delay,
    is_retryable_error,
    RETRYABLE_ERROR_CODES,
    MAX_RETRIES,
    BASE_DELAY,
    MAX_DELAY,
    EXPONENTIAL_BASE
)


# Test helper to create ClientError
def create_client_error(error_code: str, message: str = "Test error"):
    """Create a boto3 ClientError for testing."""
    return ClientError(
        error_response={
            'Error': {
                'Code': error_code,
                'Message': message
            }
        },
        operation_name='TestOperation'
    )


class TestCalculateBackoffDelay:
    """Tests for backoff delay calculation."""
    
    @given(
        attempt=st.integers(min_value=0, max_value=10),
        base_delay=st.floats(min_value=0.1, max_value=5.0),
        exponential_base=st.integers(min_value=2, max_value=3)
    )
    @settings(max_examples=100)
    def test_backoff_increases_exponentially(self, attempt, base_delay, exponential_base):
        """
        **Property 11: API retry with exponential backoff**
        
        For any attempt number, base delay, and exponential base,
        the backoff delay should increase exponentially with the attempt number.
        """
        if attempt == 0:
            # First attempt should be close to base delay
            delay = calculate_backoff_delay(
                attempt=attempt,
                base_delay=base_delay,
                exponential_base=exponential_base,
                jitter=False
            )
            assert delay == base_delay
        else:
            # Subsequent attempts should increase exponentially
            delay_prev = calculate_backoff_delay(
                attempt=attempt - 1,
                base_delay=base_delay,
                exponential_base=exponential_base,
                jitter=False
            )
            delay_curr = calculate_backoff_delay(
                attempt=attempt,
                base_delay=base_delay,
                exponential_base=exponential_base,
                jitter=False
            )
            
            # Current delay should be exponential_base times the previous
            # (unless capped by max_delay)
            if delay_prev * exponential_base <= MAX_DELAY:
                # Use approximate equality for floating point comparison
                expected = delay_prev * exponential_base
                assert abs(delay_curr - expected) < 1e-9, f"Expected {expected}, got {delay_curr}"
            else:
                assert delay_curr == MAX_DELAY
    
    @given(
        attempt=st.integers(min_value=0, max_value=20),
        base_delay=st.floats(min_value=0.1, max_value=5.0)
    )
    @settings(max_examples=100)
    def test_backoff_respects_max_delay(self, attempt, base_delay):
        """
        **Property 11: API retry with exponential backoff**
        
        For any attempt number and base delay, the backoff delay
        should never exceed the maximum delay.
        """
        delay = calculate_backoff_delay(
            attempt=attempt,
            base_delay=base_delay,
            jitter=False
        )
        assert delay <= MAX_DELAY
    
    @given(
        attempt=st.integers(min_value=0, max_value=10),
        base_delay=st.floats(min_value=0.1, max_value=5.0)
    )
    @settings(max_examples=100)
    def test_jitter_adds_randomness(self, attempt, base_delay):
        """
        **Property 11: API retry with exponential backoff**
        
        For any attempt number and base delay, when jitter is enabled,
        the delay should be between 50% and 100% of the calculated delay.
        """
        # Calculate delay without jitter
        delay_no_jitter = calculate_backoff_delay(
            attempt=attempt,
            base_delay=base_delay,
            jitter=False
        )
        
        # Calculate delay with jitter multiple times
        delays_with_jitter = [
            calculate_backoff_delay(
                attempt=attempt,
                base_delay=base_delay,
                jitter=True
            )
            for _ in range(10)
        ]
        
        # All jittered delays should be between 50% and 100% of base delay
        for delay in delays_with_jitter:
            assert delay >= delay_no_jitter * 0.5
            assert delay <= delay_no_jitter


class TestIsRetryableError:
    """Tests for retryable error detection."""
    
    @given(error_code=st.sampled_from(list(RETRYABLE_ERROR_CODES)))
    @settings(max_examples=100)
    def test_retryable_errors_are_detected(self, error_code):
        """
        **Property 11: API retry with exponential backoff**
        
        For any error code in the retryable error codes set,
        is_retryable_error should return True.
        """
        error = create_client_error(error_code)
        assert is_retryable_error(error) is True
    
    @given(
        error_code=st.text(
            alphabet=st.characters(whitelist_categories=('Lu', 'Ll')),
            min_size=1,
            max_size=50
        ).filter(lambda x: x not in RETRYABLE_ERROR_CODES)
    )
    @settings(max_examples=100)
    def test_non_retryable_errors_are_not_detected(self, error_code):
        """
        **Property 11: API retry with exponential backoff**
        
        For any error code not in the retryable error codes set,
        is_retryable_error should return False.
        """
        error = create_client_error(error_code)
        assert is_retryable_error(error) is False
    
    @given(exception=st.sampled_from([
        ValueError("test"),
        TypeError("test"),
        RuntimeError("test"),
        Exception("test")
    ]))
    @settings(max_examples=100)
    def test_non_client_errors_are_not_retryable(self, exception):
        """
        **Property 11: API retry with exponential backoff**
        
        For any exception that is not a ClientError,
        is_retryable_error should return False.
        """
        assert is_retryable_error(exception) is False


class TestRetryDecorator:
    """Tests for retry decorator."""
    
    def test_retries_on_transient_errors(self):
        """
        **Property 11: API retry with exponential backoff**
        
        For any function that fails with transient errors,
        the retry decorator should retry up to max_attempts times.
        """
        call_count = 0
        
        @retry_with_backoff(max_attempts=3, base_delay=0.01)
        def failing_function():
            nonlocal call_count
            call_count += 1
            raise create_client_error('ThrottlingException')
        
        with pytest.raises(ClientError):
            failing_function()
        
        # Should have been called 3 times (initial + 2 retries)
        assert call_count == 3
    
    def test_succeeds_after_retries(self):
        """
        **Property 11: API retry with exponential backoff**
        
        For any function that succeeds after some failures,
        the retry decorator should return the successful result.
        """
        call_count = 0
        
        @retry_with_backoff(max_attempts=3, base_delay=0.01)
        def eventually_succeeds():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise create_client_error('ThrottlingException')
            return "success"
        
        result = eventually_succeeds()
        assert result == "success"
        assert call_count == 3
    
    def test_does_not_retry_non_retryable_errors(self):
        """
        **Property 11: API retry with exponential backoff**
        
        For any function that fails with non-retryable errors,
        the retry decorator should not retry and raise immediately.
        """
        call_count = 0
        
        @retry_with_backoff(max_attempts=3, base_delay=0.01)
        def non_retryable_error():
            nonlocal call_count
            call_count += 1
            raise create_client_error('AccessDeniedException')
        
        with pytest.raises(ClientError):
            non_retryable_error()
        
        # Should have been called only once (no retries)
        assert call_count == 1
    
    @given(max_attempts=st.integers(min_value=1, max_value=5))
    @settings(max_examples=100)
    def test_respects_max_attempts(self, max_attempts):
        """
        **Property 11: API retry with exponential backoff**
        
        For any max_attempts configuration, the retry decorator
        should retry exactly max_attempts times before giving up.
        """
        call_count = 0
        
        @retry_with_backoff(max_attempts=max_attempts, base_delay=0.01)
        def always_fails():
            nonlocal call_count
            call_count += 1
            raise create_client_error('ThrottlingException')
        
        with pytest.raises(ClientError):
            always_fails()
        
        assert call_count == max_attempts


class TestRetryThroughRealClientWrapper:
    """
    Regression tests for retry across the API client's exception translation.

    IdentityCenterClient converts every botocore ClientError into
    IdentityCenterClientError with `raise ... from e`. is_retryable_error must
    therefore follow __cause__; if it only inspects the outermost exception, a
    throttled call fails on the first attempt and @retry_with_backoff is inert.

    These tests drive the REAL IdentityCenterClient and count boto3 calls. A test
    that raises ClientError from a fully-mocked client bypasses the translation
    and cannot detect this class of bug.
    """

    @staticmethod
    def _client_raising(error_code: str, counter: dict):
        from unittest.mock import Mock, patch
        from botocore.exceptions import ClientError

        err = ClientError(
            {'Error': {'Code': error_code, 'Message': 'test'}},
            'DeleteApplicationAssignment'
        )

        def _raise(**_kwargs):
            counter['n'] += 1
            raise err

        patcher = patch('identity_center_client.boto3')
        mock_boto = patcher.start()
        mock_boto.client.return_value = Mock(
            delete_application_assignment=Mock(side_effect=_raise)
        )
        from identity_center_client import IdentityCenterClient
        return IdentityCenterClient(), patcher

    def test_throttle_is_retried_through_the_client_wrapper(self):
        """A throttled delete must reach boto3 max_attempts times, not once."""
        from unittest.mock import patch
        import deletion

        counter = {'n': 0}
        client, patcher = self._client_raising('ThrottlingException', counter)
        try:
            with patch('time.sleep'):
                deletion.delete_application_assignment(
                    application_arn='arn:aws:sso::123456789012:application/ssoins-x/apl-y',
                    principal_id='11111111-1111-1111-1111-111111111111',
                    principal_type='GROUP',
                    client=client,
                )
        finally:
            patcher.stop()

        assert counter['n'] == 3, (
            f"throttled delete hit boto3 {counter['n']}x, expected 3 -- "
            "retry is not seeing the wrapped ClientError"
        )

    def test_non_retryable_error_is_not_retried(self):
        """AccessDenied is permanent; retrying wastes time and muddies logs."""
        from unittest.mock import patch
        import deletion

        counter = {'n': 0}
        client, patcher = self._client_raising('AccessDeniedException', counter)
        try:
            with patch('time.sleep'):
                deletion.delete_application_assignment(
                    application_arn='arn:aws:sso::123456789012:application/ssoins-x/apl-y',
                    principal_id='11111111-1111-1111-1111-111111111111',
                    principal_type='GROUP',
                    client=client,
                )
        finally:
            patcher.stop()

        assert counter['n'] == 1, (
            f"non-retryable error hit boto3 {counter['n']}x, expected 1"
        )
