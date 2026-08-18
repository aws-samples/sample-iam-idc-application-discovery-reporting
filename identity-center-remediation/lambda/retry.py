"""
Retry logic with exponential backoff for transient errors.

This module provides a decorator for retrying operations that may fail
due to transient errors like throttling or service unavailability.
"""

import time
import random
from functools import wraps
from typing import Callable, Any, Tuple, Type
from botocore.exceptions import ClientError


# Retry configuration
MAX_RETRIES = 3
BASE_DELAY = 1.0  # seconds
MAX_DELAY = 10.0  # seconds
EXPONENTIAL_BASE = 2

# Retryable AWS error codes
RETRYABLE_ERROR_CODES = {
    'ThrottlingException',
    'InternalServerException',
    'ServiceUnavailableException',
    'RequestTimeout',
    'InternalFailure',
    'ServiceUnavailable'
}


def calculate_backoff_delay(attempt: int, base_delay: float = BASE_DELAY, 
                            exponential_base: int = EXPONENTIAL_BASE,
                            max_delay: float = MAX_DELAY,
                            jitter: bool = True) -> float:
    """
    Calculate exponential backoff delay with optional jitter.
    
    Args:
        attempt: Current attempt number (0-indexed)
        base_delay: Base delay in seconds
        exponential_base: Base for exponential calculation
        max_delay: Maximum delay in seconds
        jitter: Whether to add random jitter
        
    Returns:
        Delay in seconds
    """
    # Calculate exponential delay: base_delay * (exponential_base ^ attempt)
    delay = base_delay * (exponential_base ** attempt)
    
    # Cap at max delay
    delay = min(delay, max_delay)
    
    # Add jitter to prevent thundering herd
    if jitter:
        # Add random jitter between 0 and delay
        delay = delay * (0.5 + random.random() * 0.5)
    
    return delay


def is_retryable_error(exception: Exception) -> bool:
    """
    Check if an exception is retryable.
    
    Args:
        exception: Exception to check
        
    Returns:
        True if exception is retryable, False otherwise
    """
    # Check if it's a boto3 ClientError with retryable error code.
    #
    # Also follow the __cause__ chain. The API client wrappers translate
    # ClientError into their own exception types with `raise ... from e`, so by
    # the time a retryable throttle reaches this decorator it is wrapped and no
    # longer a ClientError. Without walking the chain, a throttled call would
    # fail on the first attempt and the retry decorator would be inert.
    seen = set()
    current = exception
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ClientError):
            error_code = current.response.get('Error', {}).get('Code', '')
            return error_code in RETRYABLE_ERROR_CODES
        current = current.__cause__

    return False


def retry_with_backoff(
    max_attempts: int = MAX_RETRIES,
    base_delay: float = BASE_DELAY,
    max_delay: float = MAX_DELAY,
    exponential_base: int = EXPONENTIAL_BASE,
    jitter: bool = True
):
    """
    Decorator for retrying functions with exponential backoff.
    
    Retries the decorated function up to max_attempts times when it raises
    a retryable exception. Uses exponential backoff with optional jitter
    between retry attempts.
    
    Args:
        max_attempts: Maximum number of retry attempts (default: 3)
        base_delay: Base delay in seconds (default: 1.0)
        max_delay: Maximum delay in seconds (default: 10.0)
        exponential_base: Base for exponential calculation (default: 2)
        jitter: Whether to add random jitter (default: True)
        
    Returns:
        Decorated function
        
    Example:
        @retry_with_backoff(max_attempts=3, base_delay=1.0)
        def call_api():
            # API call that may fail with transient errors
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    # Attempt the function call
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    # Check if error is retryable
                    if not is_retryable_error(e):
                        # Non-retryable error, raise immediately
                        raise
                    
                    # Check if we have more attempts left
                    if attempt < max_attempts - 1:
                        # Calculate backoff delay
                        delay = calculate_backoff_delay(
                            attempt=attempt,
                            base_delay=base_delay,
                            exponential_base=exponential_base,
                            max_delay=max_delay,
                            jitter=jitter
                        )
                        
                        # Wait before retrying
                        time.sleep(delay)
                    else:
                        # No more attempts, raise the last exception
                        raise
            
            # Should never reach here, but raise last exception if we do
            if last_exception:
                raise last_exception
        
        return wrapper
    return decorator
