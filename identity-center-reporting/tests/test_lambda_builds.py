"""
Test suite for Lambda function build and compilation validation
"""
import os
import sys
import pytest
import py_compile
import tempfile
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas'))

class TestLambdaBuilds:
    """Test Lambda function compilation and imports"""
    
    @pytest.fixture
    def lambda_base_path(self):
        """Get the base path for Lambda functions"""
        return Path(__file__).parent.parent / 'src' / 'lambdas'
    
    def test_instance_scanner_compiles(self, lambda_base_path):
        """Test that instance scanner Lambda compiles"""
        index_file = lambda_base_path / 'instance-scanner' / 'index.py'
        assert index_file.exists(), "Instance scanner index.py not found"
        
        # Test compilation
        try:
            py_compile.compile(str(index_file), doraise=True)
        except py_compile.PyCompileError as e:
            pytest.fail(f"Instance scanner failed to compile: {e}")
    
    def test_application_discovery_compiles(self, lambda_base_path):
        """Test that application discovery Lambda compiles"""
        index_file = lambda_base_path / 'application-discovery' / 'index.py'
        assert index_file.exists(), "Application discovery index.py not found"
        
        try:
            py_compile.compile(str(index_file), doraise=True)
        except py_compile.PyCompileError as e:
            pytest.fail(f"Application discovery failed to compile: {e}")
    
    def test_assignment_discovery_compiles(self, lambda_base_path):
        """Test that assignment discovery Lambda compiles"""
        index_file = lambda_base_path / 'assignment-discovery' / 'index.py'
        assert index_file.exists(), "Assignment discovery index.py not found"
        
        try:
            py_compile.compile(str(index_file), doraise=True)
        except py_compile.PyCompileError as e:
            pytest.fail(f"Assignment discovery failed to compile: {e}")
        
        # Test additional modules
        for module in ['assignment_discovery.py', 'persistence.py', 'edge_cases.py']:
            module_file = lambda_base_path / 'assignment-discovery' / module
            if module_file.exists():
                try:
                    py_compile.compile(str(module_file), doraise=True)
                except py_compile.PyCompileError as e:
                    pytest.fail(f"Assignment discovery module {module} failed to compile: {e}")
    
    def test_change_detection_compiles(self, lambda_base_path):
        """Test that change detection Lambda compiles"""
        index_file = lambda_base_path / 'change-detection' / 'index.py'
        assert index_file.exists(), "Change detection index.py not found"
        
        try:
            py_compile.compile(str(index_file), doraise=True)
        except py_compile.PyCompileError as e:
            pytest.fail(f"Change detection failed to compile: {e}")
    
    def test_csv_export_compiles(self, lambda_base_path):
        """Test that CSV export Lambda compiles"""
        index_file = lambda_base_path / 'csv-export' / 'index.py'
        assert index_file.exists(), "CSV export index.py not found"
        
        try:
            py_compile.compile(str(index_file), doraise=True)
        except py_compile.PyCompileError as e:
            pytest.fail(f"CSV export failed to compile: {e}")
    
    def test_shared_modules_compile(self, lambda_base_path):
        """Test that all shared modules compile"""
        shared_path = lambda_base_path / 'shared'
        assert shared_path.exists(), "Shared modules directory not found"
        
        shared_modules = [
            'utils.py',
            'models.py',
            'monitoring.py',
            'tracing.py',
            'performance.py',
            'incremental.py',
            'alarms.py',
            'alerting.py'
        ]
        
        for module in shared_modules:
            module_file = shared_path / module
            if module_file.exists():
                try:
                    py_compile.compile(str(module_file), doraise=True)
                except py_compile.PyCompileError as e:
                    pytest.fail(f"Shared module {module} failed to compile: {e}")
    
    def test_all_lambdas_have_handler(self, lambda_base_path):
        """Test that all Lambda functions have a lambda_handler function"""
        lambda_dirs = [
            'instance-scanner',
            'application-discovery',
            'assignment-discovery',
            'change-detection',
            'csv-export'
        ]
        
        for lambda_dir in lambda_dirs:
            index_file = lambda_base_path / lambda_dir / 'index.py'
            if index_file.exists():
                content = index_file.read_text()
                assert 'def lambda_handler' in content, \
                    f"{lambda_dir} missing lambda_handler function"
    
    def test_no_syntax_errors_in_lambdas(self, lambda_base_path):
        """Test that all Python files have no syntax errors"""
        python_files = list(lambda_base_path.rglob('*.py'))
        
        errors = []
        for py_file in python_files:
            # Skip __pycache__ and test files
            if '__pycache__' in str(py_file) or 'test_' in py_file.name:
                continue
            
            try:
                with open(py_file, 'r') as f:
                    compile(f.read(), str(py_file), 'exec')
            except SyntaxError as e:
                errors.append(f"{py_file}: {e}")
        
        if errors:
            pytest.fail(f"Syntax errors found:\n" + "\n".join(errors))
    
    def test_lambda_dependencies_importable(self):
        """Test that Lambda dependencies can be imported"""
        # Test boto3 (required for all Lambdas)
        try:
            import boto3
            assert boto3.__version__
        except ImportError:
            pytest.fail("boto3 not available - required for Lambda functions")
    
    def test_shared_modules_importable(self, lambda_base_path):
        """Test that shared modules can be imported"""
        shared_path = lambda_base_path / 'shared'
        sys.path.insert(0, str(shared_path))
        
        try:
            # Test importing key shared modules
            from utils import setup_logging, handle_api_error
            from models import (
                DiscoveryResult, 
                Instance, 
                Application, 
                Assignment
            )
            from monitoring import DiscoveryMonitor
            
            # Verify classes/functions exist
            assert callable(setup_logging)
            assert callable(handle_api_error)
            assert DiscoveryResult
            assert Instance
            assert Application
            assert Assignment
            assert DiscoveryMonitor
            
        except ImportError as e:
            pytest.fail(f"Failed to import shared modules: {e}")
        finally:
            sys.path.pop(0)
    
    def test_lambda_package_structure(self, lambda_base_path):
        """Test that Lambda packages have correct structure"""
        lambda_dirs = [
            'instance-scanner',
            'application-discovery',
            'assignment-discovery',
            'change-detection',
            'csv-export'
        ]
        
        for lambda_dir in lambda_dirs:
            lambda_path = lambda_base_path / lambda_dir
            assert lambda_path.exists(), f"{lambda_dir} directory not found"
            assert (lambda_path / 'index.py').exists(), \
                f"{lambda_dir} missing index.py"
    
    def test_requirements_files_exist(self, lambda_base_path):
        """Test that requirements files exist for Lambda packaging"""
        # Check for requirements at project root
        project_root = lambda_base_path.parent.parent
        requirements_file = project_root / 'requirements.txt'
        
        assert requirements_file.exists(), \
            "requirements.txt not found at project root"
        
        # Verify it contains key dependencies
        content = requirements_file.read_text()
        assert 'boto3' in content, "boto3 not in requirements.txt"


class TestLambdaFunctionality:
    """Test Lambda function basic functionality"""

    def _import_fresh_index(self, lambda_dir):
        """Import a Lambda's index.py with a clean module cache.

        Every Lambda entrypoint is named index.py, so a cached 'index' from an
        earlier test (or another Lambda) would otherwise shadow this import.
        """
        import importlib
        saved = sys.modules.pop('index', None)
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', lambda_dir))
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'shared'))
        try:
            import index
            return importlib.reload(index) if getattr(index, '__file__', '') and lambda_dir not in index.__file__ else index
        finally:
            sys.path.pop(0)
            sys.path.pop(0)
            sys.modules.pop('index', None)
            if saved is not None:
                sys.modules['index'] = saved
    
    def test_instance_scanner_imports(self):
        """Test instance scanner can import its dependencies"""
        try:
            instance_scanner = self._import_fresh_index('instance-scanner')
            assert hasattr(instance_scanner, 'lambda_handler')
        except ImportError as e:
            pytest.fail(f"Instance scanner import failed: {e}")
    
    def test_application_discovery_imports(self):
        """Test application discovery can import its dependencies"""
        try:
            app_discovery = self._import_fresh_index('application-discovery')
            assert hasattr(app_discovery, 'lambda_handler')
        except ImportError as e:
            pytest.fail(f"Application discovery import failed: {e}")
    
    def test_assignment_discovery_imports(self):
        """Test assignment discovery can import its dependencies"""
        try:
            assignment_discovery = self._import_fresh_index('assignment-discovery')
            assert hasattr(assignment_discovery, 'lambda_handler')
        except ImportError as e:
            pytest.fail(f"Assignment discovery import failed: {e}")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
