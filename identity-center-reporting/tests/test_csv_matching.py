"""
Property-based tests for CSV export with matching metadata

Feature: sso-group-application-matching
Tests Properties 5 and 6 from the design document
"""

import pytest
import csv
import io
from hypothesis import given, strategies as st, settings, HealthCheck
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import importlib.util

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas'))

# Mock boto3 before importing csv-export module
import boto3
import importlib.util

# Load the csv-export module explicitly
csv_export_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'lambdas', 'csv-export', 'index.py')
spec = importlib.util.spec_from_file_location("csv_export_module", csv_export_path)
csv_export = importlib.util.module_from_spec(spec)

# Mock boto3 before executing the module
with patch('boto3.resource'), patch('boto3.client'):
    spec.loader.exec_module(csv_export)


# Strategies for generating test data
@st.composite
def assignment_with_metadata(draw):
    """Generate an assignment with matching metadata"""
    matched_value = draw(st.sampled_from(['Yes', 'No', 'Unknown']))
    
    assignment = {
        'assignment_id': f"apl-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}#group-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}",
        'application_arn': f"arn:aws:sso::{draw(st.integers(min_value=100000000000, max_value=999999999999))}:application/ssoins-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}/apl-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}",
        'application_name': draw(st.text(min_size=1, max_size=50)),
        'principal_id': f"group-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}",
        'principal_type': 'GROUP',
        'principal_name': draw(st.text(min_size=1, max_size=50)),
        'principal_display_name': draw(st.text(min_size=0, max_size=50)),
        'principal_email': draw(st.text(min_size=0, max_size=50)),
        'permission_set_arn': f"arn:aws:sso:::permissionSet/ssoins-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}/ps-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}",
        'permission_set_name': draw(st.text(min_size=1, max_size=50)),
        'account_id': str(draw(st.integers(min_value=100000000000, max_value=999999999999))),
        'instance_arn': f"arn:aws:sso:::instance/ssoins-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}",
        'assignment_status': 'ACTIVE',
        'last_updated': '2024-01-01T00:00:00Z',
        'matched': matched_value
    }
    
    return assignment


@st.composite
def assignment_without_metadata(draw):
    """Generate an assignment without matching metadata"""
    assignment = {
        'assignment_id': f"apl-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}#user-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}",
        'application_arn': f"arn:aws:sso::{draw(st.integers(min_value=100000000000, max_value=999999999999))}:application/ssoins-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}/apl-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}",
        'application_name': draw(st.text(min_size=1, max_size=50)),
        'principal_id': f"user-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}",
        'principal_type': 'USER',
        'principal_name': draw(st.text(min_size=1, max_size=50)),
        'principal_display_name': draw(st.text(min_size=0, max_size=50)),
        'principal_email': draw(st.text(min_size=0, max_size=50)),
        'permission_set_arn': f"arn:aws:sso:::permissionSet/ssoins-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}/ps-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}",
        'permission_set_name': draw(st.text(min_size=1, max_size=50)),
        'account_id': str(draw(st.integers(min_value=100000000000, max_value=999999999999))),
        'instance_arn': f"arn:aws:sso:::instance/ssoins-{draw(st.text(alphabet='0123456789abcdef', min_size=16, max_size=16))}",
        'assignment_status': 'ACTIVE',
        'last_updated': '2024-01-01T00:00:00Z',
        'metadata': None  # No metadata for user assignments
    }
    
    return assignment


@given(st.lists(assignment_with_metadata(), min_size=1, max_size=10))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property_5_csv_includes_matching_metadata(assignments):
    """
    Feature: sso-group-application-matching, Property 5: CSV includes matching metadata
    Validates: Requirements 2.2
    
    For any assignment with matching metadata, when exported to CSV,
    the 'Matched' column should contain the metadata value
    """
    # Mock the query_assignments function to return our test assignments
    with patch.object(csv_export, 'query_assignments', return_value=assignments):
        # Generate CSV
        csv_data, filename = csv_export.generate_assignments_csv({})
        
        # Parse CSV
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        rows = list(csv_reader)
        
        # Verify header includes "Matched" column
        assert 'Matched' in csv_reader.fieldnames, "CSV header must include 'Matched' column"
        
        # Verify each assignment's matched value is in the CSV
        for i, assignment in enumerate(assignments):
            expected_matched = assignment['matched']
            actual_matched = rows[i]['Matched']
            
            assert actual_matched == expected_matched, \
                f"Assignment {i}: Expected matched='{expected_matched}', got '{actual_matched}'"


@given(st.lists(assignment_without_metadata(), min_size=1, max_size=10))
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_property_6_csv_empty_for_missing_metadata(assignments):
    """
    Feature: sso-group-application-matching, Property 6: CSV empty for missing metadata
    Validates: Requirements 2.3
    
    For any assignment without matching metadata, when exported to CSV,
    the 'Matched' column should be empty
    """
    # Mock the query_assignments function to return our test assignments
    with patch.object(csv_export, 'query_assignments', return_value=assignments):
        # Generate CSV
        csv_data, filename = csv_export.generate_assignments_csv({})
        
        # Parse CSV
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        rows = list(csv_reader)
        
        # Verify header includes "Matched" column
        assert 'Matched' in csv_reader.fieldnames, "CSV header must include 'Matched' column"
        
        # Verify each assignment has empty matched value
        for i, assignment in enumerate(assignments):
            actual_matched = rows[i]['Matched']
            
            assert actual_matched == '', \
                f"Assignment {i}: Expected empty matched value, got '{actual_matched}'"



# Unit tests for CSV export with matching metadata

def test_assignments_csv_includes_matched_header():
    """
    Test that assignments CSV includes "Matched" header
    Requirements: 2.1
    """
    # Create a sample assignment with metadata
    assignment = {
        'assignment_id': 'apl-1234567890abcdef#group-1234567890abcdef',
        'application_arn': 'arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef',
        'application_name': 'TestApp',
        'principal_id': 'group-1234567890abcdef',
        'principal_type': 'GROUP',
        'principal_name': 'TestGroup',
        'principal_display_name': 'Test Group',
        'principal_email': '',
        'permission_set_arn': 'arn:aws:sso:::permissionSet/ssoins-1234567890abcdef/ps-1234567890abcdef',
        'permission_set_name': 'TestPermissionSet',
        'account_id': '123456789012',
        'instance_arn': 'arn:aws:sso:::instance/ssoins-1234567890abcdef',
        'assignment_status': 'ACTIVE',
        'last_updated': '2024-01-01T00:00:00Z',
        'matched': 'Yes'
    }
    
    # Mock the query_assignments function
    with patch.object(csv_export, 'query_assignments', return_value=[assignment]):
        # Generate CSV
        csv_data, filename = csv_export.generate_assignments_csv({})
        
        # Parse CSV
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        
        # Verify header includes "Matched" column
        assert 'Matched' in csv_reader.fieldnames, "CSV header must include 'Matched' column"


def test_full_csv_includes_matched_header():
    """
    Test that full CSV includes "Matched" header
    Requirements: 2.1
    """
    # Create sample data
    instance = {
        'instance_arn': 'arn:aws:sso:::instance/ssoins-1234567890abcdef',
        'account_id': '123456789012',
        'region': 'us-east-1',
        'instance_type': 'organization',
        'status': 'ACTIVE',
        'identity_store_id': 'd-1234567890',
        'last_updated': '2024-01-01T00:00:00Z'
    }
    
    application = {
        'application_arn': 'arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef',
        'instance_arn': 'arn:aws:sso:::instance/ssoins-1234567890abcdef',
        'name': 'TestApp',
        'status': 'ENABLED',
        'account_id': '123456789012',
        'region': 'us-east-1',
        'last_updated': '2024-01-01T00:00:00Z',
        'portal_options': {}
    }
    
    assignment = {
        'assignment_id': 'apl-1234567890abcdef#group-1234567890abcdef',
        'application_arn': 'arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef',
        'principal_id': 'group-1234567890abcdef',
        'principal_type': 'GROUP',
        'principal_name': 'TestGroup',
        'instance_arn': 'arn:aws:sso:::instance/ssoins-1234567890abcdef',
        'assignment_status': 'ACTIVE',
        'last_updated': '2024-01-01T00:00:00Z',
        'matched': 'Yes'
    }
    
    # Mock the query functions
    with patch.object(csv_export, 'query_instances', return_value=[instance]), \
         patch.object(csv_export, 'query_applications', return_value=[application]), \
         patch.object(csv_export, 'query_assignments', return_value=[assignment]):
        
        # Generate CSV
        csv_data, filename = csv_export.generate_full_csv({})
        
        # Parse CSV
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        
        # Verify header includes "Matched" column
        assert 'Matched' in csv_reader.fieldnames, "CSV header must include 'Matched' column"


def test_metadata_value_appears_in_csv_row():
    """
    Test that metadata value appears in CSV row
    Requirements: 2.2
    """
    # Create assignments with different metadata values
    assignments = [
        {
            'assignment_id': 'apl-1234567890abcdef#group-1111111111111111',
            'application_arn': 'arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef',
            'application_name': 'TestApp',
            'principal_id': 'group-1111111111111111',
            'principal_type': 'GROUP',
            'principal_name': 'TestGroup1',
            'principal_display_name': '',
            'principal_email': '',
            'permission_set_arn': '',
            'permission_set_name': '',
            'account_id': '123456789012',
            'instance_arn': 'arn:aws:sso:::instance/ssoins-1234567890abcdef',
            'assignment_status': 'ACTIVE',
            'last_updated': '2024-01-01T00:00:00Z',
            'matched': 'Yes'
        },
        {
            'assignment_id': 'apl-1234567890abcdef#group-2222222222222222',
            'application_arn': 'arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef',
            'application_name': 'TestApp',
            'principal_id': 'group-2222222222222222',
            'principal_type': 'GROUP',
            'principal_name': 'TestGroup2',
            'principal_display_name': '',
            'principal_email': '',
            'permission_set_arn': '',
            'permission_set_name': '',
            'account_id': '123456789012',
            'instance_arn': 'arn:aws:sso:::instance/ssoins-1234567890abcdef',
            'assignment_status': 'ACTIVE',
            'last_updated': '2024-01-01T00:00:00Z',
            'matched': 'No'
        },
        {
            'assignment_id': 'apl-1234567890abcdef#group-3333333333333333',
            'application_arn': 'arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef',
            'application_name': 'TestApp',
            'principal_id': 'group-3333333333333333',
            'principal_type': 'GROUP',
            'principal_name': 'TestGroup3',
            'principal_display_name': '',
            'principal_email': '',
            'permission_set_arn': '',
            'permission_set_name': '',
            'account_id': '123456789012',
            'instance_arn': 'arn:aws:sso:::instance/ssoins-1234567890abcdef',
            'assignment_status': 'ACTIVE',
            'last_updated': '2024-01-01T00:00:00Z',
            'matched': 'Unknown'
        }
    ]
    
    # Mock the query_assignments function
    with patch.object(csv_export, 'query_assignments', return_value=assignments):
        # Generate CSV
        csv_data, filename = csv_export.generate_assignments_csv({})
        
        # Parse CSV
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        rows = list(csv_reader)
        
        # Verify metadata values appear correctly
        assert rows[0]['Matched'] == 'Yes', "First assignment should have 'Yes' in Matched column"
        assert rows[1]['Matched'] == 'No', "Second assignment should have 'No' in Matched column"
        assert rows[2]['Matched'] == 'Unknown', "Third assignment should have 'Unknown' in Matched column"


def test_empty_value_for_missing_metadata():
    """
    Test that empty value appears for missing metadata
    Requirements: 2.3
    """
    # Create assignments without metadata (user assignments)
    assignments = [
        {
            'assignment_id': 'apl-1234567890abcdef#user-1111111111111111',
            'application_arn': 'arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef',
            'application_name': 'TestApp',
            'principal_id': 'user-1111111111111111',
            'principal_type': 'USER',
            'principal_name': 'TestUser1',
            'principal_display_name': '',
            'principal_email': '',
            'permission_set_arn': '',
            'permission_set_name': '',
            'account_id': '123456789012',
            'instance_arn': 'arn:aws:sso:::instance/ssoins-1234567890abcdef',
            'assignment_status': 'ACTIVE',
            'last_updated': '2024-01-01T00:00:00Z',
            'metadata': None
        },
        {
            'assignment_id': 'apl-1234567890abcdef#user-2222222222222222',
            'application_arn': 'arn:aws:sso::123456789012:application/ssoins-1234567890abcdef/apl-1234567890abcdef',
            'application_name': 'TestApp',
            'principal_id': 'user-2222222222222222',
            'principal_type': 'USER',
            'principal_name': 'TestUser2',
            'principal_display_name': '',
            'principal_email': '',
            'permission_set_arn': '',
            'permission_set_name': '',
            'account_id': '123456789012',
            'instance_arn': 'arn:aws:sso:::instance/ssoins-1234567890abcdef',
            'assignment_status': 'ACTIVE',
            'last_updated': '2024-01-01T00:00:00Z',
            'metadata': {}  # Empty metadata dict
        }
    ]
    
    # Mock the query_assignments function
    with patch.object(csv_export, 'query_assignments', return_value=assignments):
        # Generate CSV
        csv_data, filename = csv_export.generate_assignments_csv({})
        
        # Parse CSV
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        rows = list(csv_reader)
        
        # Verify empty values for missing metadata
        assert rows[0]['Matched'] == '', "Assignment with None metadata should have empty Matched column"
        assert rows[1]['Matched'] == '', "Assignment with empty metadata dict should have empty Matched column"


def test_query_assignments_applies_region_and_app_name_filters():
    """
    Regression: region and application_name filters were validated by the API
    but silently ignored by query_assignments, returning unfiltered org-wide
    data. Both are application attributes, so they are applied post-enrichment.
    """
    items = [
        {'application_arn': 'arn:app/a', 'account_id': '1', 'principal_type': 'GROUP'},
        {'application_arn': 'arn:app/b', 'account_id': '1', 'principal_type': 'GROUP'},
    ]
    app_info = {
        'arn:app/a': {'application_name': 'Alpha-Portal', 'region': 'us-east-1'},
        'arn:app/b': {'application_name': 'Beta-Portal', 'region': 'us-west-2'},
    }

    def fake_enrich(assignments):
        for a in assignments:
            info = app_info[a['application_arn']]
            a['application_name'] = info['application_name']
            a.setdefault('region', info['region'])
        return assignments

    mock_table = MagicMock()
    mock_table.scan.return_value = {'Items': [dict(i) for i in items]}

    with patch.object(csv_export.dynamodb, 'Table', return_value=mock_table), \
         patch.object(csv_export, 'enrich_assignments_with_app_names', side_effect=fake_enrich):
        by_region = csv_export.query_assignments({'region': 'us-west-2'})
        assert [a['application_arn'] for a in by_region] == ['arn:app/b']

    mock_table.scan.return_value = {'Items': [dict(i) for i in items]}
    with patch.object(csv_export.dynamodb, 'Table', return_value=mock_table), \
         patch.object(csv_export, 'enrich_assignments_with_app_names', side_effect=fake_enrich):
        by_name = csv_export.query_assignments({'application_name': 'alpha'})
        assert [a['application_arn'] for a in by_name] == ['arn:app/a']

    mock_table.scan.return_value = {'Items': [dict(i) for i in items]}
    with patch.object(csv_export.dynamodb, 'Table', return_value=mock_table), \
         patch.object(csv_export, 'enrich_assignments_with_app_names', side_effect=fake_enrich):
        no_match = csv_export.query_assignments({'application_name': 'nonexistent'})
        assert no_match == []
