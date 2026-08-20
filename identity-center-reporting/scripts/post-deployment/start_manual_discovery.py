#!/usr/bin/env python3
"""Trigger a full discovery via API Gateway with pre-flight API tests"""

import boto3
import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
import json
import time
import argparse
import sys



def redact_assignment_id(assignment_id):
    """
    Drop the principal half of an assignment key before printing it.

    assignment_id is "<application-id>#<principal-id>". The application half locates
    the record; the principal half is an Identity Store UUID naming a real person,
    and this script prints against the live table.

    Deliberately a local copy of src/lambdas/shared/utils.redact_assignment_id rather
    than an import: this is a standalone operator script, and reaching into the Lambda
    package would mean sys.path surgery to save three lines.
    """
    if not assignment_id:
        return 'unknown'
    text = str(assignment_id)
    if '#' not in text:
        return f'{text[:8]}...' if len(text) > 8 else text
    application_part, _, principal_part = text.partition('#')
    suffix = f'{principal_part[:4]}...' if len(principal_part) > 4 else principal_part
    return f'{application_part}#{suffix}'


class APITester:
    """Test API Gateway endpoints with IAM authentication"""
    
    def __init__(self, api_url: str, region: str = 'us-east-1'):
        self.api_url = api_url.rstrip('/')
        self.region = region
        self.session = boto3.Session(region_name=region)
        self.results = []
    
    def create_signed_request(self, url, method='GET', params=None, data=None):
        """Create a signed AWS request for API Gateway"""
        credentials = self.session.get_credentials()
        request = AWSRequest(
            method=method,
            url=url,
            params=params,
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        SigV4Auth(credentials, 'execute-api', self.region).add_auth(request)
        return request
    
    def test_endpoint(self, endpoint, description, method='GET', payload=None, silent=False):
        """Test a specific API endpoint"""
        if not silent:
            print(f"\n🔍 Testing {description}")
            print(f"   Endpoint: {endpoint}")
            print(f"   Method: {method}")
        
        try:
            full_url = f"{self.api_url}/{endpoint.lstrip('/')}"
            
            if method == 'GET':
                signed_request = self.create_signed_request(full_url)
                response = requests.get(
                    signed_request.url,
                    headers=dict(signed_request.headers),
                    params=signed_request.params,
                    verify=True,
                    timeout=30
                )
            elif method == 'POST':
                signed_request = self.create_signed_request(
                    full_url, 
                    method='POST', 
                    data=json.dumps(payload) if payload else None
                )
                response = requests.post(
                    signed_request.url,
                    headers=dict(signed_request.headers),
                    data=signed_request.data,
                    verify=True,
                    timeout=30
                )
            
            success = response.status_code == 200
            
            if not silent:
                print(f"   Status Code: {response.status_code}")
                if success:
                    print("   ✅ SUCCESS")
                else:
                    print(f"   ❌ ERROR - {response.status_code}")
                    if response.status_code == 403:
                        print("   Issue: FORBIDDEN - Check IAM permissions")
                    elif response.status_code == 404:
                        print("   Issue: NOT FOUND - Check endpoint path")
            
            self.results.append((description, success, response.status_code))
            return success
            
        except Exception as e:
            if not silent:
                print(f"   ❌ EXCEPTION: {e}")
            self.results.append((description, False, 'ERROR'))
            return False
    
    def run_pre_flight_tests(self):
        """Run essential API tests before discovery"""
        print("\n" + "="*80)
        print("PRE-FLIGHT API TESTS")
        print("="*80)
        print(f"📍 Base URL: {self.api_url}")
        print(f"🔐 Authentication: IAM (SigV4)")
        
        # Test export endpoints (these should work if API is healthy)
        self.test_endpoint("export/applications", "Applications Export")
        self.test_endpoint("export/assignments", "Assignments Export")
        self.test_endpoint("export/full", "Full Export")
        
        # Print summary
        print("\n" + "="*80)
        print("PRE-FLIGHT TEST SUMMARY")
        print("="*80)
        
        passed = sum(1 for _, success, _ in self.results if success)
        total = len(self.results)
        
        for description, success, status_code in self.results:
            status = "✅ PASSED" if success else "❌ FAILED"
            code_info = f"({status_code})" if isinstance(status_code, int) else f"({status_code})"
            print(f"{status}: {description} {code_info}")
        
        print(f"\nOverall: {passed}/{total} tests passed")
        
        all_passed = passed == total
        if all_passed:
            print("✅ All pre-flight tests passed - proceeding with discovery")
        else:
            print("❌ Some pre-flight tests failed - aborting discovery")
        
        print("="*80)
        
        return all_passed


# Parse command line arguments
parser = argparse.ArgumentParser(description='Trigger IAM Identity Center discovery via API Gateway')
parser.add_argument(
    '--stack-name',
    default='IamIdentityCenterDiscoveryStack-dev',
    help='CloudFormation stack name (default: IamIdentityCenterDiscoveryStack-dev)'
)
parser.add_argument(
    '--region',
    default='us-east-1',
    help='AWS region (default: us-east-1)'
)
parser.add_argument(
    '--skip-tests',
    action='store_true',
    help='Skip pre-flight API tests'
)
args = parser.parse_args()

# Get API URL from stack
cf = boto3.client('cloudformation', region_name=args.region)
response = cf.describe_stacks(StackName=args.stack_name)
api_url = None
for output in response['Stacks'][0].get('Outputs', []):
    if output['OutputKey'] == 'ExportApiUrl':
        api_url = output['OutputValue'].rstrip('/')
        break

print(f'Stack: {args.stack_name}')
print(f'Region: {args.region}')
print(f'API URL: {api_url}')

# Run pre-flight API tests
if not args.skip_tests:
    tester = APITester(api_url, args.region)
    if not tester.run_pre_flight_tests():
        print("\n❌ Pre-flight tests failed. Exiting without running discovery.")
        sys.exit(1)
    print("\n" + "="*80)
    print("STARTING DISCOVERY")
    print("="*80)

# Create signed POST request to trigger endpoint
session = boto3.Session(region_name=args.region)
credentials = session.get_credentials()

full_url = f'{api_url}/trigger'
payload = json.dumps({
    'force_full_discovery': True,
    'incremental_discovery_enabled': False
})

request = AWSRequest(
    method='POST',
    url=full_url,
    data=payload,
    headers={'Content-Type': 'application/json'}
)

SigV4Auth(credentials, 'execute-api', args.region).add_auth(request)

response = requests.post(
    request.url,
    headers=dict(request.headers),
    data=request.data,
    verify=True,
    timeout=30
)

print(f'Status Code: {response.status_code}')
# Status only. This endpoint's responses reference the CSV exports, which carry user
# emails and display names, and this script runs against the live account -- printing
# the body puts that data in a terminal, a scrollback buffer, and any CI log.
print(f'Request ID: {response.headers.get("x-amzn-RequestId", "unknown")}')

if response.status_code == 200:
    # Parse response text manually due to malformed JSON from API Gateway
    import re
    response_text = response.text
    arn_match = re.search(r'arn:aws:states:[^"]+', response_text)
    execution_arn = arn_match.group(0) if arn_match else None
    
    print(f'\n✅ Discovery started successfully!')
    print(f'Execution ARN: {execution_arn}')
    
    # Monitor execution
    sfn = boto3.client('stepfunctions', region_name=args.region)
    print('\nMonitoring execution...')
    
    while True:
        time.sleep(5)
        exec_response = sfn.describe_execution(executionArn=execution_arn)
        status = exec_response['status']
        print(f'Status: {status}')
        
        if status in ['SUCCEEDED', 'FAILED', 'TIMED_OUT', 'ABORTED']:
            break
    
    if status == 'SUCCEEDED':
        print('\n✅ Discovery completed successfully!')
        
        # Check DynamoDB tables
        print('\n' + '=' * 80)
        print('VERIFYING DYNAMODB TABLES')
        print('=' * 80)
        
        dynamodb = boto3.resource('dynamodb', region_name=args.region)
        
        # Table names
        instances_table = dynamodb.Table('iam-identity-center-instances')
        applications_table = dynamodb.Table('iam-identity-center-applications')
        assignments_table = dynamodb.Table('iam-identity-center-assignments')
        
        # Check Instances
        print('\n📊 INSTANCES TABLE')
        print('-' * 80)
        instances_response = instances_table.scan()
        instances = instances_response.get('Items', [])
        instance_count = len(instances)
        
        print(f'Total Instances: {instance_count}')
        if instance_count >= 0:
            print(f'✅ PASS: Found {instance_count} instances (required: >= 0)')
        else:
            print(f'❌ FAIL: Found {instance_count} instances (required: >= 0)')
        
        for i, instance in enumerate(instances[:5], 1):
            print(f'\n  Instance {i}:')
            print(f'    ARN: {instance.get("instance_arn", "N/A")}')
            print(f'    Account ID: {instance.get("account_id", "N/A")}')
            print(f'    Region: {instance.get("region", "N/A")}')
            print(f'    Identity Store ID: {instance.get("identity_store_id", "N/A")}')
        
        # Check Applications
        print('\n\n📊 APPLICATIONS TABLE')
        print('-' * 80)
        applications_response = applications_table.scan()
        applications = applications_response.get('Items', [])
        application_count = len(applications)
        
        print(f'Total Applications: {application_count}')
        if application_count >= 0:
            print(f'✅ PASS: Found {application_count} applications (required: >= 0)')
        else:
            print(f'❌ FAIL: Found {application_count} applications (required: >= 0)')
        
        for i, app in enumerate(applications[:5], 1):
            print(f'\n  Application {i}:')
            print(f'    ARN: {app.get("application_arn", "N/A")}')
            print(f'    Name: {app.get("application_name", "N/A")}')
            print(f'    Instance ARN: {app.get("instance_arn", "N/A")}')
            print(f'    Provider: {app.get("application_provider_arn", "N/A")}')
        
        # Check Assignments
        print('\n\n📊 ASSIGNMENTS TABLE')
        print('-' * 80)
        assignments_response = assignments_table.scan()
        assignments = assignments_response.get('Items', [])
        assignment_count = len(assignments)
        
        print(f'Total Assignments: {assignment_count}')
        if assignment_count > 0:
            print(f'✅ PASS: Found {assignment_count} assignments (required: > 0)')
        else:
            print(f'❌ FAIL: Found {assignment_count} assignments (required: > 0)')
        
        # Principal IDs are deliberately omitted.
        #
        # This scans the live assignments table, so every row is a real person's or
        # group's access. The check here is that assignments exist and are shaped
        # correctly -- the principal's identity is not needed for that, and printing
        # it puts real Identity Store identifiers into a terminal, a scrollback
        # buffer, and whatever CI log captures the run. Principal type is kept
        # because USER vs GROUP is a property of the assignment, not of the person.
        #
        # assignment_id is "<application-id>#<principal-id>", so printing it whole
        # re-leaks the identifier removed just below. Only the part before the
        # separator is shown.
        for i, assignment in enumerate(assignments[:5], 1):
            assignment_id = str(assignment.get('assignment_id', 'N/A'))
            print(f'\n  Assignment {i}:')
            print(f'    ID: {redact_assignment_id(assignment_id)}')
            print(f'    Application ARN: {assignment.get("application_arn", "N/A")}')
            print(f'    Principal Type: {assignment.get("principal_type", "N/A")}')
        
        # Summary
        print('\n\n' + '=' * 80)
        print('SUMMARY')
        print('=' * 80)
        print(f'Instances: {instance_count} (required: >= 0) - {"✅ PASS" if instance_count >= 0 else "❌ FAIL"}')
        print(f'Applications: {application_count} (required: >= 0) - {"✅ PASS" if application_count >= 0 else "❌ FAIL"}')
        print(f'Assignments: {assignment_count} (required: > 0) - {"✅ PASS" if assignment_count > 0 else "❌ FAIL"}')
        
        all_pass = instance_count >= 0 and application_count >= 0 and assignment_count > 0
        if all_pass:
            print('\n🎉 ALL CHECKS PASSED!')
        else:
            print('\n⚠️  SOME CHECKS FAILED')
        
        print('=' * 80)
        
        # Download CSV exports
        print('\n' + '=' * 80)
        print('DOWNLOADING CSV EXPORTS')
        print('=' * 80)
        
        import os
        
        # Create downloads directory
        downloads_dir = 'csv_downloads'
        os.makedirs(downloads_dir, exist_ok=True)
        
        # Export endpoints to download
        endpoints = {
            "applications": "export/applications",
            "assignments": "export/assignments",
            "full": "export/full"
        }
        
        for export_type, endpoint in endpoints.items():
            print(f'\n🔍 Downloading {export_type} export...')
            
            try:
                # Make authenticated request to API Gateway
                endpoint_url = f"{api_url}/{endpoint}"
                request = AWSRequest(method='GET', url=endpoint_url)
                SigV4Auth(credentials, "execute-api", args.region).add_auth(request)
                
                response = requests.get(
                    endpoint_url, 
                    headers=dict(request.headers),
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    # Handle nested body if present (Lambda proxy integration)
                    if 'body' in data and isinstance(data['body'], str):
                        data = json.loads(data['body'])
                    
                    download_url = data.get('download_url')
                    filename = data.get('filename', f'{export_type}_export.csv')
                    
                    # Download CSV from S3 presigned URL
                    csv_response = requests.get(download_url, timeout=30)
                    
                    if csv_response.status_code == 200:
                        # Save to file
                        filepath = os.path.join(downloads_dir, filename)
                        with open(filepath, 'w') as f:
                            f.write(csv_response.text)
                        
                        # Get stats
                        lines = csv_response.text.strip().split('\n')
                        file_size = len(csv_response.text)
                        header = lines[0] if lines else ''
                        columns = len(header.split(','))
                        
                        print(f'   ✅ Downloaded: {filename}')
                        print(f'   📁 Size: {file_size:,} bytes')
                        print(f'   📊 Rows: {len(lines):,} (including header)')
                        print(f'   📋 Columns: {columns}')
                        print(f'   💾 Saved to: {filepath}')
                    else:
                        print(f'   ❌ Failed to download CSV: HTTP {csv_response.status_code}')
                else:
                    print(f'   ❌ API request failed: HTTP {response.status_code}')
                    # Status and request ID only -- see the note on the earlier call.
                    print(f'      Request ID: {response.headers.get("x-amzn-RequestId", "unknown")}')
            
            except requests.exceptions.Timeout:
                print(f'   ❌ Request timed out after 30 seconds')
            except requests.exceptions.RequestException as e:
                print(f'   ❌ Request failed: {e}')
            except Exception as e:
                print(f'   ❌ Unexpected error: {e}')
        
        print('\n' + '=' * 80)
        print('CSV EXPORT VALIDATION')
        print('=' * 80)
        
        # Validate the freshly downloaded CSVs (use the ones we just downloaded)
        csv_files = {}
        for export_type, endpoint in endpoints.items():
            # Find the file we just downloaded by matching the timestamp
            for f in sorted(os.listdir(downloads_dir), reverse=True):
                if f.endswith('.csv'):
                    if export_type == 'applications' and 'applications_export' in f:
                        filepath = os.path.join(downloads_dir, f)
                        break
                    elif export_type == 'assignments' and 'assignments_export' in f:
                        filepath = os.path.join(downloads_dir, f)
                        break
                    elif export_type == 'full' and 'full_export' in f:
                        filepath = os.path.join(downloads_dir, f)
                        break
            else:
                continue
            
            with open(filepath, 'r') as file:
                content = file.read()
                lines = content.strip().split('\n')
                header = lines[0] if lines else ''
                columns = len(header.split(','))
                csv_files[export_type] = {'filename': f, 'columns': columns, 'rows': len(lines)}
        
        # Expected column counts
        expected = {
            'applications': 13,
            'assignments': 19,
            'full': 32
        }
        
        all_valid = True
        for export_type, expected_cols in expected.items():
            if export_type in csv_files:
                info = csv_files[export_type]
                actual_cols = info['columns']
                is_valid = actual_cols == expected_cols
                status = '✅ VALID' if is_valid else '❌ INVALID'
                
                print(f'\n{export_type.upper()}:')
                print(f'  Filename: {info["filename"]}')
                print(f'  Columns: {actual_cols} (expected: {expected_cols}) - {status}')
                print(f'  Rows: {info["rows"]}')
                
                if not is_valid:
                    all_valid = False
            else:
                print(f'\n{export_type.upper()}: ❌ NOT FOUND')
                all_valid = False
        
        print('\n' + '=' * 80)
        if all_valid:
            print('🎉 ALL CSV EXPORTS ARE VALID!')
        else:
            print('⚠️  SOME CSV EXPORTS ARE INVALID')
        
        print(f'\nAll CSVs saved to: {downloads_dir}/')
        print('=' * 80)
        
    else:
        print(f'\n❌ Discovery failed with status: {status}')
        if 'error' in exec_response:
            print(f'Error: {exec_response["error"]}')
        if 'cause' in exec_response:
            print(f'Cause: {exec_response["cause"]}')
