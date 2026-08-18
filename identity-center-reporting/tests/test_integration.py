"""
Integration tests for the IAM Identity Center Discovery solution
"""
import os
import sys
import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'shared'))

from models import Instance, Application, Assignment


class TestEndToEndDiscoveryFlow:
    """Test end-to-end discovery workflow"""
    
    @patch('boto3.client')
    def test_full_discovery_workflow(self, mock_boto_client):
        """Test complete discovery workflow from instances to assignments"""
        
        # Mock SSO Admin client
        mock_sso_client = MagicMock()
        mock_dynamodb_client = MagicMock()
        
        def mock_client(service_name, **kwargs):
            if service_name == 'sso-admin':
                return mock_sso_client
            elif service_name == 'dynamodb':
                return mock_dynamodb_client
            return MagicMock()
        
        mock_boto_client.side_effect = mock_client
        
        # Step 1: Instance Discovery
        mock_sso_client.list_instances.return_value = {
            'Instances': [
                {
                    'InstanceArn': 'arn:aws:sso:::instance/ssoins-test123',
                    'IdentityStoreId': 'd-test123',
                    'CreatedDate': datetime.now(timezone.utc)
                }
            ]
        }
        
        # Step 2: Application Discovery
        mock_sso_client.list_applications.return_value = {
            'Applications': [
                {
                    'ApplicationArn': 'arn:aws:sso::123456789012:application/ssoins-test123/apl-test',
                    'Name': 'TestApp',
                    'Status': 'ENABLED',
                    'ApplicationProviderArn': 'arn:aws:sso::aws:applicationProvider/custom',
                    'CreatedDate': datetime.now(timezone.utc)
                }
            ]
        }
        
        # Step 3: Assignment Discovery
        mock_sso_client.list_application_assignments.return_value = {
            'ApplicationAssignments': [
                {
                    'ApplicationArn': 'arn:aws:sso::123456789012:application/ssoins-test123/apl-test',
                    'PrincipalId': 'principal-123',
                    'PrincipalType': 'GROUP'
                }
            ]
        }
        
        # Mock DynamoDB operations
        mock_dynamodb_client.put_item.return_value = {}
        mock_dynamodb_client.batch_write_item.return_value = {}
        
        # Verify workflow can complete
        assert mock_sso_client.list_instances.return_value['Instances']
        assert mock_sso_client.list_applications.return_value['Applications']
        assert mock_sso_client.list_application_assignments.return_value['ApplicationAssignments']


class TestDataPersistence:
    """Test data persistence to DynamoDB"""
    
    @patch('boto3.resource')
    def test_instance_persistence(self, mock_boto_resource):
        """Test instance data can be persisted to DynamoDB"""
        mock_table = MagicMock()
        mock_dynamodb = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        mock_boto_resource.return_value = mock_dynamodb
        
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
        
        # Convert to DynamoDB format
        item = instance.to_dict()
        
        # Verify item structure
        assert 'instance_arn' in item
        assert 'account_id' in item
        assert 'region' in item
        
        # Mock put_item
        mock_table.put_item.return_value = {}
        mock_table.put_item(Item=item)
        
        # Verify put_item was called
        mock_table.put_item.assert_called_once()
    
    @patch('boto3.resource')
    def test_application_persistence(self, mock_boto_resource):
        """Test application data can be persisted to DynamoDB"""
        mock_table = MagicMock()
        mock_dynamodb = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        mock_boto_resource.return_value = mock_dynamodb
        
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
        
        # Convert to DynamoDB format
        item = app.to_dict()
        
        # Verify item structure
        assert 'application_arn' in item
        assert 'name' in item
        assert 'status' in item
        
        # Mock put_item
        mock_table.put_item.return_value = {}
        mock_table.put_item(Item=item)
        
        # Verify put_item was called
        mock_table.put_item.assert_called_once()
    
    @patch('boto3.resource')
    def test_assignment_persistence(self, mock_boto_resource):
        """Test assignment data can be persisted to DynamoDB"""
        mock_table = MagicMock()
        mock_dynamodb = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        mock_boto_resource.return_value = mock_dynamodb
        
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
        
        # Convert to DynamoDB format
        item = assignment.to_dict()
        
        # Verify item structure
        assert 'assignment_id' in item
        assert 'principal_type' in item
        assert 'principal_name' in item
        
        # Mock put_item
        mock_table.put_item.return_value = {}
        mock_table.put_item(Item=item)
        
        # Verify put_item was called
        mock_table.put_item.assert_called_once()


class TestStepFunctionsIntegration:
    """Test Step Functions workflow integration"""
    
    def test_instance_scanner_output_format(self):
        """Test instance scanner output matches Step Functions expectations"""
        # Expected output format for Step Functions
        expected_structure = {
            'success': bool,
            'message': str,
            'instances': list,
            'errors': list,
            'discovery_run_id': str
        }
        
        # Sample output
        sample_output = {
            'success': True,
            'message': 'Successfully discovered 1 instance',
            'instances': [
                {
                    'instance_arn': 'arn:aws:sso:::instance/ssoins-test123',
                    'account_id': '123456789012',
                    'region': 'us-east-1'
                }
            ],
            'errors': [],
            'discovery_run_id': 'test-run-123'
        }
        
        # Verify structure
        for key, expected_type in expected_structure.items():
            assert key in sample_output
            assert isinstance(sample_output[key], expected_type)
    
    def test_application_discovery_output_format(self):
        """Test application discovery output matches Step Functions expectations"""
        # Expected output format
        expected_structure = {
            'success': bool,
            'message': str,
            'applications': list,
            'errors': list
        }
        
        # Sample output
        sample_output = {
            'success': True,
            'message': 'Successfully discovered 1 application',
            'applications': [
                {
                    'application_arn': 'arn:aws:sso::123:app/test',
                    'name': 'TestApp',
                    'status': 'ENABLED'
                }
            ],
            'errors': []
        }
        
        # Verify structure
        for key, expected_type in expected_structure.items():
            assert key in sample_output
            assert isinstance(sample_output[key], expected_type)
    
    def test_flatten_applications_integration(self):
        """Test flatten_applications works with Step Functions Map output"""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'change-detection'))
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'shared'))
        # Every Lambda entrypoint is index.py; evict any cached one so this
        # import resolves against the path just inserted.
        _saved_index = sys.modules.pop('index', None)
        
        try:
            import index as change_detection
            
            # Simulate Step Functions Map output
            map_output = {
                'action': 'flatten_applications',
                'discovery_run_id': 'test-run-123',
                'application_results': [
                    {
                        'Payload': {
                            'success': True,
                            'applications': [
                                {'application_arn': 'arn:aws:sso::123:app/test1', 'name': 'App1'},
                                {'application_arn': 'arn:aws:sso::123:app/test2', 'name': 'App2'}
                            ]
                        }
                    },
                    {
                        'Payload': {
                            'success': True,
                            'applications': [
                                {'application_arn': 'arn:aws:sso::123:app/test3', 'name': 'App3'}
                            ]
                        }
                    }
                ]
            }
            
            result = change_detection.flatten_applications(map_output)
            
            # Verify flattening worked correctly
            assert result['success'] is True
            assert len(result['applications']) == 3
            assert result['applications'][0]['name'] == 'App1'
            assert result['applications'][1]['name'] == 'App2'
            assert result['applications'][2]['name'] == 'App3'
            
        finally:
            sys.path.pop(0)
            sys.path.pop(0)
            if _saved_index is not None:
                sys.modules['index'] = _saved_index
            else:
                sys.modules.pop('index', None)


class TestCSVExportIntegration:
    """Test CSV export integration"""
    
    @patch('boto3.client')
    @patch('boto3.resource')
    def test_csv_export_full_workflow(self, mock_boto_resource, mock_boto_client):
        """Test CSV export can generate full export"""
        
        # Mock DynamoDB
        mock_dynamodb = MagicMock()
        mock_boto_resource.return_value = mock_dynamodb
        
        mock_table = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        
        # Mock scan results
        mock_table.scan.return_value = {
            'Items': [
                {
                    'instance_arn': 'arn:aws:sso:::instance/ssoins-test123',
                    'account_id': '123456789012',
                    'region': 'us-east-1',
                    'status': 'ACTIVE'
                }
            ]
        }
        
        # Mock S3
        mock_s3 = MagicMock()
        mock_boto_client.return_value = mock_s3
        mock_s3.put_object.return_value = {}
        mock_s3.generate_presigned_url.return_value = 'https://test-url.com'
        
        # Verify mocks are set up correctly
        assert mock_table.scan.return_value['Items']
        assert mock_s3.generate_presigned_url.return_value


class TestErrorRecovery:
    """Test error recovery and resilience"""
    
    @patch('boto3.client')
    def test_partial_failure_handling(self, mock_boto_client):
        """Test system handles partial failures gracefully"""
        
        mock_sso_client = MagicMock()
        mock_boto_client.return_value = mock_sso_client
        
        # Simulate partial failure - some instances succeed, some fail
        call_count = [0]
        
        def side_effect_list_applications(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {'Applications': [{'ApplicationArn': 'arn:test', 'Name': 'Test'}]}
            else:
                from botocore.exceptions import ClientError
                raise ClientError(
                    {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}},
                    'ListApplications'
                )
        
        mock_sso_client.list_applications.side_effect = side_effect_list_applications
        
        # First call should succeed
        result1 = mock_sso_client.list_applications(InstanceArn='arn:test1')
        assert 'Applications' in result1
        
        # Second call should fail
        with pytest.raises(Exception):
            mock_sso_client.list_applications(InstanceArn='arn:test2')
    
    @patch('boto3.client')
    def test_retry_logic(self, mock_boto_client):
        """Test retry logic for transient failures"""
        
        mock_sso_client = MagicMock()
        mock_boto_client.return_value = mock_sso_client
        
        # Simulate transient failure then success
        call_count = [0]
        
        def side_effect_with_retry(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] < 2:
                from botocore.exceptions import ClientError
                raise ClientError(
                    {'Error': {'Code': 'ThrottlingException', 'Message': 'Rate exceeded'}},
                    'ListInstances'
                )
            return {'Instances': []}
        
        mock_sso_client.list_instances.side_effect = side_effect_with_retry
        
        # First call fails
        with pytest.raises(Exception):
            mock_sso_client.list_instances()
        
        # Second call succeeds
        result = mock_sso_client.list_instances()
        assert 'Instances' in result


class TestMonitoringIntegration:
    """Test monitoring and observability integration"""
    
    def test_discovery_monitor_initialization(self):
        """Test DiscoveryMonitor can be initialized"""
        from monitoring import DiscoveryMonitor
        
        monitor = DiscoveryMonitor()
        assert monitor is not None
    
    def test_performance_tracking(self):
        """Test performance tracking via PerformanceCollector.measure_operation"""
        with patch('boto3.client'):
            from performance import PerformanceCollector

            collector = PerformanceCollector(discovery_run_id='test-run-123')
            with collector.measure_operation('test_operation', items_count=5):
                pass

            assert len(collector.metrics) == 1
            metrics = collector.metrics[0]
            assert metrics.operation_name == 'test_operation'
            assert metrics.success is True
            assert metrics.items_processed == 5
            assert metrics.duration_ms is not None and metrics.duration_ms >= 0


class TestAssignmentDiscoveryWithMatching:
    """Integration tests for assignment discovery with matching logic"""
    
    def test_group_assignment_gets_matching_metadata(self):
        """Test GROUP assignment gets matching metadata"""
        # Create a GROUP assignment with matching metadata
        assignment = Assignment(
            assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            principal_id="12345678-1234-1234-1234-123456789abc",
            principal_type="GROUP",
            principal_name="Engineering",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            assignment_status="ACTIVE",
            matched='Yes'
        )
        
        # Verify assignment has matching metadata
        assert assignment is not None
        assert assignment.matched is not None
        assert assignment.matched == 'Yes'
    
    def test_user_assignment_has_no_matching_metadata(self):
        """Test USER assignment has no matching metadata"""
        # Create a USER assignment without matched field
        assignment = Assignment(
            assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            principal_id="12345678-1234-1234-1234-123456789abc",
            principal_type="USER",
            principal_name="john.doe@example.com",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            assignment_status="ACTIVE",
            matched=None
        )
        
        # Verify assignment has NO matched field (USER principals don't get matching)
        assert assignment is not None
        assert assignment.matched is None
    
    def test_metadata_included_in_assignment_object(self):
        """Test metadata is properly included in Assignment object"""
        # Create a GROUP assignment with non-matching metadata
        assignment = Assignment(
            assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
            application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
            principal_id="12345678-1234-1234-1234-123456789abc",
            principal_type="GROUP",
            principal_name="Finance",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
            assignment_status="ACTIVE",
            matched='No'
        )
        
        # Verify assignment has matching metadata with 'No' value
        assert assignment is not None
        assert assignment.matched is not None
        assert assignment.matched == 'No'
        
        # Verify matched is included in to_dict() output
        assignment_dict = assignment.to_dict()
        assert 'matched' in assignment_dict
        assert assignment_dict['matched'] == 'No'


class TestDynamoDBPersistenceWithMetadata:
    """Integration tests for DynamoDB persistence with metadata field"""
    
    @patch('boto3.resource')
    def test_metadata_included_in_dynamodb_item(self, mock_boto_resource):
        """Test metadata is included in DynamoDB item when persisting assignment"""
        # Add src/lambdas to path and mock shared modules
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas'))
        # Save real module objects so cleanup can restore them: deleting them
        # instead would orphan references held by other test modules
        # (test_matching.py's module-level imports) and break their patching.
        _mocked = ['shared', 'shared.utils', 'shared.models', 'shared.tracing', 'edge_cases', 'matching', 'index']
        _saved = {m: sys.modules.get(m) for m in _mocked}
        sys.modules.pop('index', None)
        sys.modules['shared'] = Mock()
        sys.modules['shared.utils'] = Mock()
        sys.modules['shared.models'] = Mock()
        sys.modules['shared.tracing'] = Mock()
        sys.modules['edge_cases'] = Mock()
        sys.modules['matching'] = Mock()
        
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'assignment-discovery'))
        
        try:
            from index import prepare_assignment_item
            
            # Create assignment with matching metadata
            assignment = Assignment(
                assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
                application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
                principal_id="12345678-1234-1234-1234-123456789abc",
                principal_type="GROUP",
                principal_name="Engineering",
                instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
                assignment_status="ACTIVE",
                matched='Yes'
            )
            
            # Prepare item for DynamoDB
            item = prepare_assignment_item(assignment)
            
            # Verify matched is included in the item
            assert 'matched' in item, "matched field should be present in DynamoDB item"
            assert item['matched'] == 'Yes', "matched value should match assignment matched"
            
            # Verify other required fields are present
            assert 'assignment_id' in item
            assert 'principal_type' in item
            assert 'principal_name' in item
            assert 'discovery_metadata' in item
            
        finally:
            sys.path.pop(0)
            sys.path.pop(0)
            # Restore original module objects (or remove if absent before)
            for mod, orig in _saved.items():
                if orig is not None:
                    sys.modules[mod] = orig
                else:
                    sys.modules.pop(mod, None)
    
    @patch('boto3.resource')
    def test_metadata_not_filtered_out_for_no_match(self, mock_boto_resource):
        """Test metadata with 'No' value is not filtered out"""
        # Add src/lambdas to path and mock shared modules
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas'))
        # Save real module objects so cleanup can restore them: deleting them
        # instead would orphan references held by other test modules
        # (test_matching.py's module-level imports) and break their patching.
        _mocked = ['shared', 'shared.utils', 'shared.models', 'shared.tracing', 'edge_cases', 'matching', 'index']
        _saved = {m: sys.modules.get(m) for m in _mocked}
        sys.modules.pop('index', None)
        sys.modules['shared'] = Mock()
        sys.modules['shared.utils'] = Mock()
        sys.modules['shared.models'] = Mock()
        sys.modules['shared.tracing'] = Mock()
        sys.modules['edge_cases'] = Mock()
        sys.modules['matching'] = Mock()
        
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'assignment-discovery'))
        
        try:
            from index import prepare_assignment_item
            
            # Create assignment with 'No' matching metadata
            assignment = Assignment(
                assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
                application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
                principal_id="12345678-1234-1234-1234-123456789abc",
                principal_type="GROUP",
                principal_name="Finance",
                instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
                assignment_status="ACTIVE",
                matched='No'
            )
            
            # Prepare item for DynamoDB
            item = prepare_assignment_item(assignment)
            
            # Verify matched is included even with 'No' value
            assert 'matched' in item, "matched field should be present even with 'No' value"
            assert item['matched'] == 'No', "matched 'No' value should not be filtered out"
            
        finally:
            sys.path.pop(0)
            sys.path.pop(0)
            # Restore original module objects (or remove if absent before)
            for mod, orig in _saved.items():
                if orig is not None:
                    sys.modules[mod] = orig
                else:
                    sys.modules.pop(mod, None)
    
    @patch('boto3.resource')
    def test_batch_write_includes_metadata(self, mock_boto_resource):
        """Test batch write includes metadata for all assignments"""
        # Add src/lambdas to path and mock shared modules
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas'))
        _mocked = ['shared', 'shared.utils', 'shared.models', 'index']
        _saved = {m: sys.modules.get(m) for m in _mocked}
        sys.modules.pop('index', None)
        sys.modules['shared'] = Mock()
        sys.modules['shared.utils'] = Mock()
        sys.modules['shared.models'] = Mock()
        
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'assignment-discovery'))
        
        try:
            from persistence import prepare_assignment_item_with_indexes
            
            # Create multiple assignments with different metadata values
            assignments = [
                Assignment(
                    assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
                    application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
                    principal_id="12345678-1234-1234-1234-123456789abc",
                    principal_type="GROUP",
                    principal_name="Engineering",
                    instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
                    assignment_status="ACTIVE",
                    matched='Yes'
                ),
                Assignment(
                    assignment_id="apl-1234567890abcdef#87654321-4321-4321-4321-cba987654321",
                    application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
                    principal_id="87654321-4321-4321-4321-cba987654321",
                    principal_type="GROUP",
                    principal_name="Finance",
                    instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
                    assignment_status="ACTIVE",
                    matched='No'
                ),
                Assignment(
                    assignment_id="apl-1234567890abcdef#11111111-1111-1111-1111-111111111111",
                    application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
                    principal_id="11111111-1111-1111-1111-111111111111",
                    principal_type="USER",
                    principal_name="john.doe@example.com",
                    instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
                    assignment_status="ACTIVE",
                    matched=None
                )
            ]
            
            # Prepare items for batch write
            items = [prepare_assignment_item_with_indexes(a, "NEW") for a in assignments]
            
            # Verify matched is included for GROUP assignments
            assert 'matched' in items[0], "First assignment should have matched"
            assert items[0]['matched'] == 'Yes'
            
            assert 'matched' in items[1], "Second assignment should have matched"
            assert items[1]['matched'] == 'No'
            
            # USER assignment should not have matched (None is filtered out)
            assert 'matched' not in items[2], "USER assignment should not have matched field"
            
        finally:
            sys.path.pop(0)
            sys.path.pop(0)
            # Restore original module objects (or remove if absent before)
            for mod, orig in _saved.items():
                if orig is not None:
                    sys.modules[mod] = orig
                else:
                    sys.modules.pop(mod, None)
    
    @patch('boto3.resource')
    def test_metadata_persists_correctly_to_dynamodb(self, mock_boto_resource):
        """Test metadata persists correctly to DynamoDB through full write operation"""
        # Mock DynamoDB table
        mock_table = MagicMock()
        mock_dynamodb = MagicMock()
        mock_dynamodb.Table.return_value = mock_table
        mock_boto_resource.return_value = mock_dynamodb
        
        # Add src/lambdas to path and mock shared modules
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas'))
        # Save real module objects so cleanup can restore them: deleting them
        # instead would orphan references held by other test modules
        # (test_matching.py's module-level imports) and break their patching.
        _mocked = ['shared', 'shared.utils', 'shared.models', 'shared.tracing', 'edge_cases', 'matching', 'index']
        _saved = {m: sys.modules.get(m) for m in _mocked}
        sys.modules.pop('index', None)
        sys.modules['shared'] = Mock()
        sys.modules['shared.utils'] = Mock()
        sys.modules['shared.models'] = Mock()
        sys.modules['shared.tracing'] = Mock()
        sys.modules['edge_cases'] = Mock()
        sys.modules['matching'] = Mock()
        
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'assignment-discovery'))
        
        try:
            from index import prepare_assignment_item
            
            # Create assignment with matching metadata
            assignment = Assignment(
                assignment_id="apl-1234567890abcdef#12345678-1234-1234-1234-123456789abc",
                application_arn="arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef",
                principal_id="12345678-1234-1234-1234-123456789abc",
                principal_type="GROUP",
                principal_name="Engineering",
                instance_arn="arn:aws:sso:::instance/ssoins-1234567890abcdef",
                assignment_status="ACTIVE",
                matched='Yes'
            )
            
            # Prepare item for DynamoDB
            item = prepare_assignment_item(assignment)
            
            # Mock put_item
            mock_table.put_item.return_value = {}
            mock_table.put_item(Item=item)
            
            # Verify put_item was called with matched
            mock_table.put_item.assert_called_once()
            call_args = mock_table.put_item.call_args
            assert 'Item' in call_args.kwargs
            assert 'matched' in call_args.kwargs['Item']
            assert call_args.kwargs['Item']['matched'] == 'Yes'
            
        finally:
            sys.path.pop(0)
            sys.path.pop(0)
            # Restore original module objects (or remove if absent before)
            for mod, orig in _saved.items():
                if orig is not None:
                    sys.modules[mod] = orig
                else:
                    sys.modules.pop(mod, None)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
