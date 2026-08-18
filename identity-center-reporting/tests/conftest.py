"""
Pytest configuration and fixtures for test isolation.

This module provides fixtures to ensure proper test isolation by cleaning up
module state between tests.
"""

import pytest
import sys


@pytest.fixture(scope="function", autouse=True)
def reset_matching_state(request):
    """
    Reset matching module state before and after each test.
    
    This ensures that module-level variables in the matching module
    don't persist between tests.
    """
    # Reset before test
    if 'matching' in sys.modules:
        try:
            import matching
            matching._cloudwatch_client = None
            matching._metrics_enabled = True
        except (ImportError, AttributeError):
            pass
    
    yield
    
    # Reset after test - this is critical to prevent pollution
    # Force reset even if the module was modified during the test
    if 'matching' in sys.modules:
        try:
            import matching
            # Force reset the CloudWatch client to None
            # This prevents pollution from integration tests that call real matching functions
            matching._cloudwatch_client = None
            matching._metrics_enabled = True
            
            # Also reset any boto3 clients that might have been created
            try:
                import importlib
                importlib.reload(matching)
                matching._cloudwatch_client = None
                matching._metrics_enabled = True
            except:
                pass
        except (ImportError, AttributeError):
            pass


@pytest.fixture(scope="function", autouse=True)
def cleanup_lambda_modules():
    """Clean up Lambda index modules after each test to prevent pollution"""
    yield
    
    # Remove 'index' modules that might have been imported during tests
    modules_to_remove = [key for key in sys.modules.keys() if key == 'index' or key.endswith('.index')]
    for module_name in modules_to_remove:
        try:
            del sys.modules[module_name]
        except KeyError:
            pass
