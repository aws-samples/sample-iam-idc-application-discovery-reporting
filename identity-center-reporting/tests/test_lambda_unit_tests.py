"""
Unit tests for Lambda function business logic
"""
import os
import sys
import json
import pytest
import importlib
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'shared'))


@pytest.fixture(autouse=True)
def cleanup_lambda_modules():
    """Clean up Lambda modules after each test"""
    modules_to_remove = []
    
    # Track which modules are added during the test
    original_modules = set(sys.modules.keys())
    
    yield
    
    # Remove modules that were added during the test
    current_modules = set(sys.modules.keys())
    new_modules = current_modules - original_modules
    
    for module_name in new_modules:
        if 'index' in module_name or 'lambda' in module_name.lower():
            try:
                del sys.modules[module_name]
            except KeyError:
                pass

from models import (
    DiscoveryResult,
    Instance,
    Application,
    Assignment
)
from utils import setup_logging, handle_api_error


class TestSharedModels:
    """Test shared data models"""
    
    def test_discovery_result_creation(self):
        """Test DiscoveryResult model creation"""
        result = DiscoveryResult(
            success=True,
            message="Test successful",
            data=[],
            errors=[]
        )
        
        assert result.success is True
        assert result.message == "Test successful"
        assert result.data == []
        assert result.errors == []
    
    def test_instance_creation(self):
        """Test Instance model creation"""
        instance = Instance(
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            account_id="123456789012",
            region="us-east-1",
            instance_type="organization",
            status="ACTIVE",
            identity_store_id="d-1234567890",
            created_date=datetime.now(timezone.utc).isoformat(),
            last_updated=datetime.now(timezone.utc).isoformat()
        )
        
        assert instance.instance_arn == "arn:aws:sso:::instance/ssoins-1234567890abcdef"
        assert instance.account_id == "123456789012"
        assert instance.region == "us-east-1"
        assert instance.instance_type == "organization"
        assert instance.status == "ACTIVE"
    
    def test_instance_to_dict(self):
        """Test Instance serialization"""
        instance = Instance(
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            account_id="123456789012",
            region="us-east-1",
            instance_type="organization",
            status="ACTIVE",
            identity_store_id="d-1234567890",
            created_date=datetime.now(timezone.utc).isoformat(),
            last_updated=datetime.now(timezone.utc).isoformat()
        )
        
        instance_dict = instance.to_dict()
        
        assert isinstance(instance_dict, dict)
        assert instance_dict['instance_arn'] == "arn:aws:sso:::instance/ssoins-1234567890abcdef"
        assert instance_dict['account_id'] == "123456789012"
        assert 'created_date' in instance_dict
    
    def test_application_creation(self):
        """Test Application model creation"""
        app = Application(
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            name="Test Application",
            description="Test Description",
            status="ENABLED",
            application_provider_arn="arn:aws:sso::aws:applicationProvider/custom",
            account_id="123456789012",
            region="us-east-1",
            created_date=datetime.now(timezone.utc).isoformat(),
            last_updated=datetime.now(timezone.utc).isoformat()
        )
        
        assert app.application_arn == "arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef"
        assert app.name == "Test Application"
        assert app.status == "ENABLED"

    def test_application_accepts_multi_segment_provider_arn(self):
        """Regression: AWS-managed provider ARNs may carry a multi-segment path
        (e.g. .../app-fe1c614acd2b4858/WIP). These must validate, not be dropped."""
        app = Application(
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            name="AccountAccess",
            description="",
            status="ENABLED",
            application_provider_arn="arn:aws:sso::aws:applicationProvider/app-fe1c614acd2b4858/WIP",
            account_id="123456789012",
            region="us-east-1",
            created_date=datetime.now(timezone.utc).isoformat(),
            last_updated=datetime.now(timezone.utc).isoformat()
        )
        assert app._is_valid_provider_arn(
            "arn:aws:sso::aws:applicationProvider/app-fe1c614acd2b4858/WIP"
        )
        # Single-segment provider ARNs still validate; malformed ones still fail
        assert app._is_valid_provider_arn("arn:aws:sso::aws:applicationProvider/sagemakerstudio")
        assert not app._is_valid_provider_arn("arn:aws:sso::aws:applicationProvider/")

    def test_arn_validators_accept_govcloud_china_and_case_variants(self):
        """Regression: ARN validators must be partition-aware and charset-correct.

        The prior hex-only + hardcoded-aws-partition patterns silently dropped
        GovCloud/China deployments and any ARN whose id contained uppercase or a
        dot, at __post_init__ validation time.
        """
        app = Application(
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            name="Regex probe",
            status="ENABLED",
            account_id="123456789012",
            region="us-east-1",
        )
        assignment = Assignment(
            assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            principal_id="12345678-1234-1234-1234-123456789abc",
            principal_type="GROUP",
            principal_name="Team",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
        )

        # GovCloud / China partitions accepted across all validators
        assert app._is_valid_application_arn(
            "arn:aws-us-gov:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef"
        )
        assert app._is_valid_instance_arn("arn:aws-cn:sso:::instance/ssoins-1234567890abcdef")
        assert assignment._is_valid_permission_set_arn(
            "arn:aws-us-gov:sso:::permissionSet/ssoins-1234567890abcdef/ps-1234567890abcdef"
        )
        assert app._is_valid_provider_arn("arn:aws-cn:sso::aws:applicationProvider/custom")

        # Uppercase application ids are valid (real ids are not hex-only)
        assert app._is_valid_application_arn(
            "arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-ABCdef1234567890"
        )

        # Genuinely malformed ARNs are still rejected (guard against over-loosening)
        assert not app._is_valid_application_arn("arn:aws:sso::123:application/foo/bar")
        assert not app._is_valid_instance_arn("not-an-arn")

    def test_assignment_creation(self):
        """Test Assignment model creation"""
        assignment = Assignment(
            assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            principal_id="12345678-1234-1234-1234-123456789abc",
            principal_type="GROUP",
            principal_name="TestGroup",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            assignment_status="ACTIVE",
            last_updated=datetime.now(timezone.utc).isoformat()
        )
        
        assert assignment.assignment_id == "apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc"
        assert assignment.principal_type == "GROUP"
        assert assignment.principal_name == "TestGroup"
        assert assignment.assignment_status == "ACTIVE"
    
    def test_assignment_creation_with_metadata(self):
        """Test Assignment creation with matched field"""
        matched = "Yes"
        assignment = Assignment(
            assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            principal_id="12345678-1234-1234-1234-123456789abc",
            principal_type="GROUP",
            principal_name="TestGroup",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            assignment_status="ACTIVE",
            last_updated=datetime.now(timezone.utc).isoformat(),
            matched=matched
        )
        
        assert assignment.matched == "Yes"
    
    def test_assignment_creation_without_metadata(self):
        """Test Assignment creation without matched field (None)"""
        assignment = Assignment(
            assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            principal_id="12345678-1234-1234-1234-123456789abc",
            principal_type="USER",
            principal_name="TestUser",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            assignment_status="ACTIVE",
            last_updated=datetime.now(timezone.utc).isoformat()
        )
        
        assert assignment.matched is None
    
    def test_assignment_to_dict_includes_metadata(self):
        """Test to_dict() includes matched field"""
        matched = "No"
        assignment = Assignment(
            assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            principal_id="12345678-1234-1234-1234-123456789abc",
            principal_type="GROUP",
            principal_name="TestGroup",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            assignment_status="ACTIVE",
            last_updated=datetime.now(timezone.utc).isoformat(),
            matched=matched
        )
        
        assignment_dict = assignment.to_dict()
        
        assert isinstance(assignment_dict, dict)
        assert "matched" in assignment_dict
        assert assignment_dict["matched"] == "No"
    
    def test_assignment_to_dict_with_none_metadata(self):
        """Test to_dict() includes matched field when None"""
        assignment = Assignment(
            assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            principal_id="12345678-1234-1234-1234-123456789abc",
            principal_type="USER",
            principal_name="TestUser",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            assignment_status="ACTIVE",
            last_updated=datetime.now(timezone.utc).isoformat()
        )
        
        assignment_dict = assignment.to_dict()
        
        assert isinstance(assignment_dict, dict)
        assert "matched" in assignment_dict
        assert assignment_dict["matched"] is None
    
    def test_assignment_from_dict_handles_metadata(self):
        """Test from_dict() handles matched field"""
        data = {
            "assignment_id": "apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
            "application_arn": "arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            "principal_id": "12345678-1234-1234-1234-123456789abc",
            "principal_type": "GROUP",
            "principal_name": "TestGroup",
            "instance_arn": "arn:aws:sso:::instance/ssoins-1234567890abcdef",
            "assignment_status": "ACTIVE",
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "matched": "Yes"
        }
        
        assignment = Assignment.from_dict(data)
        
        assert assignment.matched == "Yes"
    
    def test_assignment_from_dict_without_metadata(self):
        """Test from_dict() handles missing matched field"""
        data = {
            "assignment_id": "apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
            "application_arn": "arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            "principal_id": "12345678-1234-1234-1234-123456789abc",
            "principal_type": "USER",
            "principal_name": "TestUser",
            "instance_arn": "arn:aws:sso:::instance/ssoins-1234567890abcdef",
            "assignment_status": "ACTIVE",
            "last_updated": datetime.now(timezone.utc).isoformat()
        }
        
        assignment = Assignment.from_dict(data)
        
        assert assignment.matched is None


class TestSharedUtils:
    """Test shared utility functions"""
    
    def test_setup_logging(self):
        """Test logging setup"""
        logger = setup_logging("test_logger")
        
        assert logger is not None
        assert logger.name == "test_logger"
    
    def test_handle_api_error_with_client_error(self):
        """Test API error handling for ClientError"""
        from botocore.exceptions import ClientError
        
        error = ClientError(
            {
                'Error': {
                    'Code': 'AccessDenied',
                    'Message': 'Access denied'
                }
            },
            'TestOperation'
        )
        
        result = handle_api_error(error)
        
        assert 'statusCode' in result
        assert result['statusCode'] in [403, 500]
        assert 'body' in result
    
    def test_handle_api_error_with_generic_exception(self):
        """Test API error handling for generic exceptions"""
        error = Exception("Test error")
        
        result = handle_api_error(error)
        
        assert 'statusCode' in result
        assert result['statusCode'] == 500
        assert 'body' in result


class TestInstanceScannerLogic:
    """Test instance scanner business logic"""
    
    @patch('boto3.client')
    def test_instance_scanner_handler_structure(self, mock_boto_client):
        """Test instance scanner handler accepts correct input"""
        # Add src/lambdas to path so 'shared' can be imported as a package
        lambdas_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas')
        instance_scanner_path = os.path.join(lambdas_path, 'instance-scanner')
        
        sys.path.insert(0, lambdas_path)
        sys.path.insert(0, instance_scanner_path)
        
        try:
            # Mock all the shared module imports before importing the handler
            with patch.dict('sys.modules', {
                'shared': MagicMock(),
                'shared.utils': MagicMock(),
                'shared.models': MagicMock(),
                'shared.alerting': MagicMock(),
                'shared.tracing': MagicMock(),
            }):
                # Mock the tracing decorator
                sys.modules['shared.tracing'].trace_lambda_handler = lambda f: f
                sys.modules['shared.tracing'].init_xray_tracing = MagicMock()
                
                import index as instance_scanner
                
                # Mock AWS clients
                mock_sso_client = MagicMock()
                mock_sso_client.list_instances.return_value = {
                    'Instances': []
                }
                mock_boto_client.return_value = mock_sso_client
                
                # Test with valid event
                event = {
                    'discovery_run_id': 'test-run-123',
                    'discovery_type': 'full'
                }
                context = MagicMock()
                
                # Should not raise exception
                result = instance_scanner.lambda_handler(event, context)
                
                assert isinstance(result, dict), "Handler should return a dictionary"
                assert 'success' in result or 'Payload' in result or 'instances' in result
            
        finally:
            # Clean up sys.path
            if lambdas_path in sys.path:
                sys.path.remove(lambdas_path)
            if instance_scanner_path in sys.path:
                sys.path.remove(instance_scanner_path)


class TestApplicationDiscoveryLogic:
    """Test application discovery business logic"""
    
    @patch('boto3.client')
    def test_application_discovery_handler_structure(self, mock_boto_client):
        """Test application discovery handler accepts correct input"""
        # Add src/lambdas to path so 'shared' can be imported as a package
        lambdas_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas')
        app_discovery_path = os.path.join(lambdas_path, 'application-discovery')
        
        sys.path.insert(0, lambdas_path)
        sys.path.insert(0, app_discovery_path)
        
        try:
            # Mock all the shared module imports before importing the handler
            with patch.dict('sys.modules', {
                'shared': MagicMock(),
                'shared.utils': MagicMock(),
                'shared.models': MagicMock(),
                'shared.alerting': MagicMock(),
                'shared.tracing': MagicMock(),
            }):
                # Mock the tracing decorator
                sys.modules['shared.tracing'].trace_lambda_handler = lambda f: f
                sys.modules['shared.tracing'].init_xray_tracing = MagicMock()
                
                import index as app_discovery
                
                # Mock AWS clients
                mock_sso_client = MagicMock()
                mock_sso_client.list_applications.return_value = {
                    'Applications': []
                }
                mock_boto_client.return_value = mock_sso_client
                
                # Test with valid event
                event = {
                    'instance_arn': 'arn:aws:sso:::instance/ssoins-test123',
                    'account_id': '123456789012',
                    'region': 'us-east-1'
                }
                context = MagicMock()
                
                # Should not raise exception
                result = app_discovery.lambda_handler(event, context)
                
                # Check result structure
                assert isinstance(result, dict)
                assert 'success' in result or 'applications' in result
            
        finally:
            # Clean up sys.path
            if lambdas_path in sys.path:
                sys.path.remove(lambdas_path)
            if app_discovery_path in sys.path:
                sys.path.remove(app_discovery_path)


class TestAssignmentDiscoveryLogic:
    """Test assignment discovery business logic"""
    
    @patch('boto3.client')
    @patch('boto3.resource')
    def test_assignment_discovery_handler_structure(self, mock_boto_resource, mock_boto_client):
        """Test assignment discovery handler accepts correct input"""
        # Add src/lambdas to path so 'shared' can be imported as a package
        lambdas_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas')
        assignment_discovery_path = os.path.join(lambdas_path, 'assignment-discovery')
        
        sys.path.insert(0, lambdas_path)
        sys.path.insert(0, assignment_discovery_path)
        
        try:
            # Mock all the shared module imports before importing the handler
            with patch.dict('sys.modules', {
                'shared': MagicMock(),
                'shared.utils': MagicMock(),
                'shared.models': MagicMock(),
                'shared.alerting': MagicMock(),
                'shared.tracing': MagicMock(),
            }):
                # Mock the tracing decorator
                sys.modules['shared.tracing'].trace_lambda_handler = lambda f: f
                sys.modules['shared.tracing'].init_xray_tracing = MagicMock()
                
                # Mock handle_api_error to return a proper dict
                sys.modules['shared.utils'].handle_api_error = MagicMock(return_value={
                    'statusCode': 500,
                    'body': json.dumps({'error': 'Test error'})
                })
                
                import index as assignment_discovery
                
                # Mock AWS clients
                mock_sso_client = MagicMock()
                mock_sso_client.list_application_assignments.return_value = {
                    'ApplicationAssignments': []
                }
                mock_boto_client.return_value = mock_sso_client
                
                # Mock DynamoDB resource
                mock_dynamodb = MagicMock()
                mock_table = MagicMock()
                mock_dynamodb.Table.return_value = mock_table
                mock_boto_resource.return_value = mock_dynamodb
                
                # Test with valid event
                event = {
                    'application_arn': 'arn:aws:sso::123456789012:application/ssoins-test/apl-test',
                    'instance_arn': 'arn:aws:sso:::instance/ssoins-test123',
                    'account_id': '123456789012',
                    'region': 'us-east-1'
                }
                context = MagicMock()
                
                # Should not raise exception
                result = assignment_discovery.lambda_handler(event, context)
                
                # Check result structure
                assert isinstance(result, dict)
            
        finally:
            # Clean up sys.path
            if lambdas_path in sys.path:
                sys.path.remove(lambdas_path)
            if assignment_discovery_path in sys.path:
                sys.path.remove(assignment_discovery_path)


class TestChangeDetectionLogic:
    """Test change detection business logic"""

    def test_check_eligibility_action_returns_should_run_incremental(self):
        """Regression: the discovery state machine invokes change-detection with
        action='check_eligibility' and then routes on
        $.Payload.body.should_run_incremental. The handler must dispatch that
        action to the eligibility check (not fall through to full-discovery
        change detection, which omits the field and breaks the Choice state)."""
        if 'index' in sys.modules:
            del sys.modules['index']

        lambdas_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas')
        change_detection_path = os.path.join(lambdas_path, 'change-detection')
        sys.path.insert(0, lambdas_path)
        sys.path.insert(0, change_detection_path)

        try:
            with patch.dict('sys.modules', {
                'shared': MagicMock(),
                'shared.tracing': MagicMock(),
                'shared.incremental': MagicMock(),
                'shared.monitoring': MagicMock(),
                'shared.utils': MagicMock(),
            }):
                sys.modules['shared.tracing'].trace_lambda_handler = lambda f: f
                sys.modules['shared.tracing'].init_xray_tracing = MagicMock()
                sys.modules['shared.utils'].setup_logging = lambda *a, **k: __import__('logging').getLogger('test')
                sys.modules['shared.utils'].handle_api_error = lambda e: {'statusCode': 500, 'body': {}}

                import index as change_detection

                with patch.object(change_detection, 'IncrementalDiscoveryManager') as mock_mgr:
                    instance = mock_mgr.return_value
                    instance.should_run_incremental_discovery.return_value = (True, "changes detected")
                    instance.create_incremental_discovery_plan.return_value = {"scope": "incremental"}

                    event = {
                        'action': 'check_eligibility',
                        'discovery_run_id': 'test-run-id',
                        'force_full_discovery': False,
                    }
                    result = change_detection.lambda_handler(event, MagicMock())

                assert result['statusCode'] == 200
                assert 'should_run_incremental' in result['body'], \
                    "check_eligibility must return body.should_run_incremental"
                assert result['body']['should_run_incremental'] is True
                assert 'incremental_plan' in result['body']
                # The InitializeIncrementalDiscovery state reads
                # $.Payload.body.discovery_run_id and $.Payload.body.incremental_plan,
                # so both must live under body (not at the top level).
                assert result['body'].get('discovery_run_id') == 'test-run-id'
                assert result['body']['incremental_plan'] == {"scope": "incremental"}
        finally:
            if 'index' in sys.modules:
                del sys.modules['index']
            if lambdas_path in sys.path:
                sys.path.remove(lambdas_path)
            if change_detection_path in sys.path:
                sys.path.remove(change_detection_path)

    def test_state_machine_incremental_paths_match_eligibility_output(self):
        """Regression (H1): the EvaluateIncrementalDecision Choice reads
        $.Payload.body.should_run_incremental, so InitializeIncrementalDiscovery
        must read its inputs from $.Payload.body.* (the eligibility Lambda nests
        discovery_run_id/incremental_plan under body), not $.Payload.*."""
        sm_path = os.path.join(
            os.path.dirname(__file__), '..', 'src', 'step-functions',
            'discovery-state-machine.json')
        with open(sm_path) as f:
            sm = json.load(f)
        states = sm['States']

        choice_var = states['EvaluateIncrementalDecision']['Choices'][0]['Variable']
        assert choice_var == '$.Payload.body.should_run_incremental'

        init = states['InitializeIncrementalDiscovery']['Parameters']
        assert init['discovery_run_id.$'] == '$.Payload.body.discovery_run_id', \
            "InitializeIncrementalDiscovery must read discovery_run_id from $.Payload.body"
        assert init['incremental_plan.$'] == '$.Payload.body.incremental_plan', \
            "InitializeIncrementalDiscovery must read incremental_plan from $.Payload.body"

    def test_full_change_detection_parses_map_results(self):
        """Regression (H2): handle_full_discovery_change_detection must read the
        flattened applications list and json.loads each assignment Map result's
        body string, not iterate dict keys (which silently yields 0 changes)."""
        if 'index' in sys.modules:
            del sys.modules['index']
        lambdas_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas')
        change_detection_path = os.path.join(lambdas_path, 'change-detection')
        sys.path.insert(0, lambdas_path)
        sys.path.insert(0, change_detection_path)
        try:
            with patch.dict('sys.modules', {
                'shared': MagicMock(),
                'shared.tracing': MagicMock(),
                'shared.incremental': MagicMock(),
                'shared.monitoring': MagicMock(),
                'shared.utils': MagicMock(),
            }):
                sys.modules['shared.tracing'].trace_lambda_handler = lambda f: f
                sys.modules['shared.tracing'].init_xray_tracing = MagicMock()
                sys.modules['shared.utils'].setup_logging = lambda *a, **k: __import__('logging').getLogger('test')
                sys.modules['shared.utils'].handle_api_error = lambda e: {'statusCode': 500, 'body': {}}

                import index as change_detection

                with patch.object(change_detection, 'IncrementalDiscoveryManager') as mock_mgr, \
                     patch.object(change_detection, 'DiscoveryMonitor'):
                    inst = mock_mgr.return_value
                    captured = {}

                    def _cap_apps(apps, rid):
                        captured['apps'] = apps
                        return []

                    def _cap_assignments(asg, rid):
                        captured['assignments'] = asg
                        return []

                    inst.detect_application_changes.side_effect = _cap_apps
                    inst.detect_assignment_changes.side_effect = _cap_assignments
                    inst.get_change_summary.return_value = {}

                    event = {
                        'action': 'detect_changes',
                        'discovery_run_id': 'run-1',
                        'discovery_type': 'full',
                        'discovery_results': {
                            'discovery_run_id': 'run-1',
                            'applications': [{'application_arn': 'apl-1', 'name': 'App1'}],
                            'assignment_results': [
                                {'Payload': {'statusCode': 200,
                                             'body': json.dumps({'assignments': [
                                                 {'assignment_id': 'apl-1#g1', 'principal_type': 'GROUP'}]})}}
                            ],
                        },
                    }
                    result = change_detection.lambda_handler(event, MagicMock())

                assert result['statusCode'] == 200
                assert captured.get('apps') == [{'application_arn': 'apl-1', 'name': 'App1'}], \
                    "applications must be read from the flattened list"
                assert captured.get('assignments') == [{'assignment_id': 'apl-1#g1', 'principal_type': 'GROUP'}], \
                    "assignment bodies must be json.loads'd from Map results"
        finally:
            if 'index' in sys.modules:
                del sys.modules['index']
            if lambdas_path in sys.path:
                sys.path.remove(lambdas_path)
            if change_detection_path in sys.path:
                sys.path.remove(change_detection_path)


class TestCSVExportLogic:
    """Test CSV export business logic"""
    
    @patch('boto3.resource')
    @patch('boto3.client')
    def test_csv_export_handler_structure(self, mock_boto_client, mock_boto_resource):
        """Test CSV export handler accepts correct input"""
        # Clear any previously imported 'index' module to avoid conflicts
        if 'index' in sys.modules:
            del sys.modules['index']
        
        # Add src/lambdas to path so 'shared' can be imported as a package
        lambdas_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas')
        csv_export_path = os.path.join(lambdas_path, 'csv-export')
        
        sys.path.insert(0, lambdas_path)
        sys.path.insert(0, csv_export_path)
        
        try:
            # Mock all the shared module imports before importing the handler
            with patch.dict('sys.modules', {
                'shared': MagicMock(),
                'shared.tracing': MagicMock(),
            }):
                # Mock the tracing decorator
                sys.modules['shared.tracing'].trace_lambda_handler = lambda f: f
                sys.modules['shared.tracing'].init_xray_tracing = MagicMock()
                
                import index as csv_export
                
                # Mock AWS clients
                mock_dynamodb = MagicMock()
                mock_s3 = MagicMock()
                
                def mock_client(service_name, **kwargs):
                    if service_name == 'dynamodb':
                        return mock_dynamodb
                    elif service_name == 's3':
                        return mock_s3
                    return MagicMock()
                
                mock_boto_client.side_effect = mock_client
                
                # Mock DynamoDB scan
                mock_dynamodb.scan.return_value = {
                    'Items': []
                }
                
                # Mock S3 put_object
                mock_s3.put_object.return_value = {}
                mock_s3.generate_presigned_url.return_value = 'https://test-url.com'
                
                # Test with valid event
                event = {
                    'export_type': 'applications',
                    'format': 'csv'
                }
                context = MagicMock()
                context.aws_request_id = 'test-request-123'
                
                # Should not raise exception
                result = csv_export.lambda_handler(event, context)
                
                # Check result structure
                assert isinstance(result, dict)
                assert 'statusCode' in result
            
        finally:
            # Clean up sys.path
            if lambdas_path in sys.path:
                sys.path.remove(lambdas_path)
            if csv_export_path in sys.path:
                sys.path.remove(csv_export_path)


class TestErrorHandling:
    """Test error handling across Lambda functions"""
    
    def test_missing_required_parameters(self):
        """Test Lambda functions handle missing parameters"""
        # Clear any previously imported 'index' module to avoid conflicts
        if 'index' in sys.modules:
            del sys.modules['index']
        
        # Add src/lambdas to path so 'shared' can be imported as a package
        lambdas_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas')
        app_discovery_path = os.path.join(lambdas_path, 'application-discovery')
        
        sys.path.insert(0, lambdas_path)
        sys.path.insert(0, app_discovery_path)
        
        try:
            # Mock all the shared module imports before importing the handler
            with patch.dict('sys.modules', {
                'shared': MagicMock(),
                'shared.utils': MagicMock(),
                'shared.models': MagicMock(),
                'shared.alerting': MagicMock(),
                'shared.tracing': MagicMock(),
            }):
                # Mock the tracing decorator
                sys.modules['shared.tracing'].trace_lambda_handler = lambda f: f
                sys.modules['shared.tracing'].init_xray_tracing = MagicMock()
                
                # Mock handle_api_error to return a proper dict
                sys.modules['shared.utils'].handle_api_error = MagicMock(return_value={
                    'statusCode': 400,
                    'body': json.dumps({'error': 'Missing required parameters'})
                })
                
                import index as app_discovery
                
                # Test with missing required fields
                event = {}
                context = MagicMock()
                context.aws_request_id = 'test-request-456'
                
                result = app_discovery.lambda_handler(event, context)
                
                # Should return error response, not raise exception
                assert isinstance(result, dict)
            
        finally:
            # Clean up sys.path
            if lambdas_path in sys.path:
                sys.path.remove(lambdas_path)
            if app_discovery_path in sys.path:
                sys.path.remove(app_discovery_path)
    
    # NOTE: This test is disabled because it tests an internal function
    # that should be tested through the lambda_handler, not directly
    # @patch.dict(os.environ, {'AWS_DEFAULT_REGION': 'us-east-1'})
    # def test_invalid_input_types(self):
    #     """Test Lambda functions handle invalid input types"""
    #     pass


class TestDataValidation:
    """Test data validation in Lambda functions"""
    
    def test_instance_arn_format(self):
        """Test instance ARN format validation"""
        valid_arns = [
            "arn:aws:sso:::instance/ssoins-1234567890abcdef",
            "arn:aws:sso:::instance/ssoins-abcd1234efgh5678"
        ]
        
        for arn in valid_arns:
            assert arn.startswith("arn:aws:sso:::instance/")
            assert "ssoins-" in arn
    
    def test_application_arn_format(self):
        """Test application ARN format validation"""
        valid_arns = [
            "arn:aws:sso::123456789012:application/ssoins-test/apl-test123",
            "arn:aws:sso::987654321098:application/ssoins-prod/apl-prod456"
        ]
        
        for arn in valid_arns:
            assert arn.startswith("arn:aws:sso::")
            assert ":application/" in arn
            assert "apl-" in arn


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
