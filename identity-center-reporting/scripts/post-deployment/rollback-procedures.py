#!/usr/bin/env python3
"""
Rollback procedures for IAM Identity Center Discovery Solution
Provides safe rollback mechanisms with data preservation options
"""

import argparse
import json
import time
import boto3
from typing import Dict, List, Optional, Tuple
from botocore.exceptions import ClientError
import sys
from datetime import datetime, timedelta


class RollbackManager:
    """Manages rollback procedures for the IAM Identity Center Discovery Solution"""
    
    def __init__(self, stack_name: str, region: str):
        self.stack_name = stack_name
        self.region = region
        
        # Initialize AWS clients
        self.session = boto3.Session(region_name=region)
        self.cloudformation = self.session.client('cloudformation')
        self.dynamodb = self.session.client('dynamodb')
        self.s3 = self.session.client('s3')
        self.lambda_client = self.session.client('lambda')
        self.stepfunctions = self.session.client('stepfunctions')
        
        self.backup_metadata = {}
    
    def create_data_backup(self) -> bool:
        """Create backup of critical data before rollback"""
        print("💾 Creating data backup before rollback...")
        
        backup_timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        backup_bucket = f"iam-identity-center-backups-{self.session.get_credentials().access_key[:8].lower()}"
        
        try:
            # Create backup bucket if it doesn't exist
            try:
                self.s3.head_bucket(Bucket=backup_bucket)
            except ClientError as e:
                if e.response['Error']['Code'] == '404':
                    print(f"   Creating backup bucket: {backup_bucket}")
                    self.s3.create_bucket(Bucket=backup_bucket)
                    
                    # Enable versioning
                    self.s3.put_bucket_versioning(
                        Bucket=backup_bucket,
                        VersioningConfiguration={'Status': 'Enabled'}
                    )
                    
                    # Enable encryption
                    self.s3.put_bucket_encryption(
                        Bucket=backup_bucket,
                        ServerSideEncryptionConfiguration={
                            'Rules': [{
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'AES256'
                                }
                            }]
                        }
                    )
            
            # Backup DynamoDB tables
            tables_to_backup = [
                'iam-identity-center-instances',
                'iam-identity-center-applications', 
                'iam-identity-center-assignments'
            ]
            
            backup_success = True
            
            for table_name in tables_to_backup:
                try:
                    backup_key = f"dynamodb-backups/{backup_timestamp}/{table_name}.json"
                    
                    if self.backup_dynamodb_table(table_name, backup_bucket, backup_key):
                        print(f"   ✅ Backed up table: {table_name}")
                        self.backup_metadata[table_name] = {
                            'bucket': backup_bucket,
                            'key': backup_key,
                            'timestamp': backup_timestamp
                        }
                    else:
                        print(f"   ❌ Failed to backup table: {table_name}")
                        backup_success = False
                        
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ResourceNotFoundException':
                        print(f"   ⚠️  Table not found: {table_name}")
                    else:
                        print(f"   ❌ Error backing up {table_name}: {e}")
                        backup_success = False
            
            # Backup CSV export bucket contents. The bucket name is
            # CloudFormation-generated, so resolve it from the stack outputs
            # rather than guessing a pattern.
            try:
                export_bucket = self.get_export_bucket_name()
                if export_bucket and self.backup_s3_bucket_contents(export_bucket, backup_bucket, f"s3-backups/{backup_timestamp}/exports/"):
                    print(f"   ✅ Backed up export bucket contents")
                else:
                    print(f"   ⚠️  Could not backup export bucket contents")
            except Exception as e:
                print(f"   ⚠️  Export bucket backup warning: {e}")
            
            # Save backup metadata
            metadata_key = f"backup-metadata/{backup_timestamp}/metadata.json"
            self.s3.put_object(
                Bucket=backup_bucket,
                Key=metadata_key,
                Body=json.dumps(self.backup_metadata, indent=2),
                ContentType='application/json'
            )
            
            print(f"✅ Data backup completed. Metadata saved to: s3://{backup_bucket}/{metadata_key}")
            return backup_success
            
        except Exception as e:
            print(f"❌ Data backup failed: {e}")
            return False
    
    def get_export_bucket_name(self) -> Optional[str]:
        """Resolve the CSV export bucket name from the stack's outputs"""
        try:
            response = self.cloudformation.describe_stacks(StackName=self.stack_name)
            for output in response['Stacks'][0].get('Outputs', []):
                if output['OutputKey'] == 'CsvExportBucketName':
                    return output['OutputValue']
        except ClientError as e:
            print(f"     Could not resolve export bucket from stack outputs: {e}")
        return None

    def backup_dynamodb_table(self, table_name: str, backup_bucket: str, backup_key: str) -> bool:
        """Backup a single DynamoDB table to S3"""
        try:
            # Scan table and collect all items
            items = []
            scan_kwargs = {'TableName': table_name}
            
            while True:
                response = self.dynamodb.scan(**scan_kwargs)
                items.extend(response.get('Items', []))
                
                if 'LastEvaluatedKey' not in response:
                    break
                
                scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            
            # Convert to JSON and upload to S3
            backup_data = {
                'table_name': table_name,
                'backup_timestamp': datetime.utcnow().isoformat(),
                'item_count': len(items),
                'items': items
            }
            
            self.s3.put_object(
                Bucket=backup_bucket,
                Key=backup_key,
                Body=json.dumps(backup_data, indent=2, default=str),
                ContentType='application/json'
            )
            
            return True
            
        except Exception as e:
            print(f"     Error backing up table {table_name}: {e}")
            return False
    
    def backup_s3_bucket_contents(self, source_bucket: str, backup_bucket: str, backup_prefix: str) -> bool:
        """Backup contents of S3 bucket"""
        try:
            # List objects in source bucket
            response = self.s3.list_objects_v2(Bucket=source_bucket)
            
            if 'Contents' not in response:
                return True  # Empty bucket, nothing to backup
            
            # Copy each object to backup bucket
            for obj in response['Contents']:
                source_key = obj['Key']
                backup_key = f"{backup_prefix}{source_key}"
                
                copy_source = {'Bucket': source_bucket, 'Key': source_key}
                self.s3.copy_object(
                    CopySource=copy_source,
                    Bucket=backup_bucket,
                    Key=backup_key
                )
            
            return True
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucket':
                return True  # Source bucket doesn't exist, nothing to backup
            else:
                print(f"     Error backing up S3 bucket {source_bucket}: {e}")
                return False
    
    def stop_running_executions(self) -> bool:
        """Stop any running Step Functions executions"""
        print("⏹️  Stopping running Step Functions executions...")
        
        try:
            # Find state machines
            response = self.stepfunctions.list_state_machines()
            discovery_sms = [
                sm for sm in response['stateMachines']
                if 'iam-identity-center-discovery' in sm['name']
            ]
            
            if not discovery_sms:
                print("   No discovery state machines found")
                return True
            
            stopped_count = 0
            
            for sm in discovery_sms:
                # List running executions
                executions_response = self.stepfunctions.list_executions(
                    stateMachineArn=sm['stateMachineArn'],
                    statusFilter='RUNNING'
                )
                
                # Stop each running execution
                for execution in executions_response['executions']:
                    try:
                        self.stepfunctions.stop_execution(
                            executionArn=execution['executionArn'],
                            cause='Stopped for rollback procedure'
                        )
                        stopped_count += 1
                        print(f"   Stopped execution: {execution['name']}")
                    except ClientError as e:
                        print(f"   Warning: Could not stop execution {execution['name']}: {e}")
            
            print(f"✅ Stopped {stopped_count} running executions")
            return True
            
        except Exception as e:
            print(f"❌ Error stopping executions: {e}")
            return False
    
    def perform_stack_rollback(self, rollback_type: str = 'update') -> bool:
        """Perform CloudFormation stack rollback"""
        print(f"🔄 Performing {rollback_type} rollback...")
        
        try:
            # Check current stack status
            response = self.cloudformation.describe_stacks(StackName=self.stack_name)
            stack = response['Stacks'][0]
            current_status = stack['StackStatus']
            
            print(f"   Current stack status: {current_status}")
            
            if rollback_type == 'update':
                if current_status in ['UPDATE_IN_PROGRESS', 'UPDATE_ROLLBACK_IN_PROGRESS']:
                    print("   Stack update already in progress, cancelling...")
                    self.cloudformation.cancel_update_stack(StackName=self.stack_name)
                elif current_status in ['UPDATE_FAILED', 'UPDATE_ROLLBACK_FAILED']:
                    print("   Continuing existing rollback...")
                    self.cloudformation.continue_update_rollback(StackName=self.stack_name)
                else:
                    print(f"   Stack status {current_status} does not require update rollback")
                    return True
                
                # Wait for rollback to complete
                print("   Waiting for rollback to complete...")
                waiter = self.cloudformation.get_waiter('stack_update_rollback_complete')
                waiter.wait(
                    StackName=self.stack_name,
                    WaiterConfig={'Delay': 30, 'MaxAttempts': 60}
                )
                
            elif rollback_type == 'delete':
                if current_status in ['CREATE_FAILED', 'ROLLBACK_COMPLETE']:
                    print("   Deleting failed stack...")
                    self.cloudformation.delete_stack(StackName=self.stack_name)
                    
                    # Wait for deletion to complete
                    print("   Waiting for stack deletion to complete...")
                    waiter = self.cloudformation.get_waiter('stack_delete_complete')
                    waiter.wait(
                        StackName=self.stack_name,
                        WaiterConfig={'Delay': 30, 'MaxAttempts': 60}
                    )
                else:
                    print(f"   Cannot delete stack in status: {current_status}")
                    return False
            
            print("✅ Stack rollback completed successfully")
            return True
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ValidationError':
                print(f"   Stack not found: {self.stack_name}")
                return True  # Stack doesn't exist, rollback not needed
            else:
                print(f"❌ Stack rollback failed: {e}")
                return False
        except Exception as e:
            print(f"❌ Stack rollback error: {e}")
            return False
    
    def restore_data_from_backup(self, backup_timestamp: str) -> bool:
        """Restore data from a previous backup"""
        print(f"📥 Restoring data from backup: {backup_timestamp}")
        
        backup_bucket = f"iam-identity-center-backups-{self.session.get_credentials().access_key[:8].lower()}"
        
        try:
            # Load backup metadata
            metadata_key = f"backup-metadata/{backup_timestamp}/metadata.json"
            response = self.s3.get_object(Bucket=backup_bucket, Key=metadata_key)
            backup_metadata = json.loads(response['Body'].read())
            
            # Restore each table
            restore_success = True
            
            for table_name, backup_info in backup_metadata.items():
                try:
                    if self.restore_dynamodb_table(table_name, backup_info):
                        print(f"   ✅ Restored table: {table_name}")
                    else:
                        print(f"   ❌ Failed to restore table: {table_name}")
                        restore_success = False
                except Exception as e:
                    print(f"   ❌ Error restoring {table_name}: {e}")
                    restore_success = False
            
            return restore_success
            
        except Exception as e:
            print(f"❌ Data restore failed: {e}")
            return False
    
    def restore_dynamodb_table(self, table_name: str, backup_info: Dict) -> bool:
        """Restore a single DynamoDB table from backup"""
        try:
            # Download backup data
            response = self.s3.get_object(
                Bucket=backup_info['bucket'],
                Key=backup_info['key']
            )
            backup_data = json.loads(response['Body'].read())
            
            # Check if table exists
            try:
                self.dynamodb.describe_table(TableName=table_name)
                table_exists = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    table_exists = False
                else:
                    raise
            
            if not table_exists:
                print(f"     Table {table_name} does not exist, cannot restore data")
                return False
            
            # Clear existing data (optional - could be made configurable)
            print(f"     Clearing existing data from {table_name}...")
            self.clear_dynamodb_table(table_name)
            
            # Restore items in batches
            items = backup_data['items']
            batch_size = 25  # DynamoDB batch write limit
            
            for i in range(0, len(items), batch_size):
                batch = items[i:i + batch_size]
                
                request_items = {
                    table_name: [
                        {'PutRequest': {'Item': item}}
                        for item in batch
                    ]
                }
                
                self.dynamodb.batch_write_item(RequestItems=request_items)
            
            print(f"     Restored {len(items)} items to {table_name}")
            return True
            
        except Exception as e:
            print(f"     Error restoring table {table_name}: {e}")
            return False
    
    def clear_dynamodb_table(self, table_name: str):
        """Clear all items from a DynamoDB table"""
        try:
            # Get table key schema
            table_response = self.dynamodb.describe_table(TableName=table_name)
            key_schema = table_response['Table']['KeySchema']
            
            # Extract key attribute names
            key_attrs = [key['AttributeName'] for key in key_schema]
            
            # Scan table and delete all items
            scan_kwargs = {
                'TableName': table_name,
                'ProjectionExpression': ','.join(key_attrs)
            }
            
            while True:
                response = self.dynamodb.scan(**scan_kwargs)
                
                if not response.get('Items'):
                    break
                
                # Delete items in batches
                delete_requests = [
                    {'DeleteRequest': {'Key': {attr: item[attr] for attr in key_attrs}}}
                    for item in response['Items']
                ]
                
                # Split into batches of 25
                for i in range(0, len(delete_requests), 25):
                    batch = delete_requests[i:i + 25]
                    self.dynamodb.batch_write_item(
                        RequestItems={table_name: batch}
                    )
                
                if 'LastEvaluatedKey' not in response:
                    break
                
                scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
                
        except Exception as e:
            print(f"     Warning: Could not clear table {table_name}: {e}")
    
    def list_available_backups(self) -> List[str]:
        """List available backups"""
        backup_bucket = f"iam-identity-center-backups-{self.session.get_credentials().access_key[:8].lower()}"
        
        try:
            response = self.s3.list_objects_v2(
                Bucket=backup_bucket,
                Prefix='backup-metadata/',
                Delimiter='/'
            )
            
            backups = []
            for prefix in response.get('CommonPrefixes', []):
                # Extract timestamp from prefix
                timestamp = prefix['Prefix'].split('/')[-2]
                backups.append(timestamp)
            
            return sorted(backups, reverse=True)  # Most recent first
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucket':
                return []
            else:
                print(f"Error listing backups: {e}")
                return []
    
    def perform_complete_rollback(self, preserve_data: bool = True, rollback_type: str = 'update') -> bool:
        """Perform complete rollback procedure"""
        print("🔄 Starting complete rollback procedure...")
        print(f"   Stack: {self.stack_name}")
        print(f"   Region: {self.region}")
        print(f"   Preserve Data: {preserve_data}")
        print(f"   Rollback Type: {rollback_type}")
        print()
        
        success = True
        
        # Step 1: Create data backup if requested
        if preserve_data:
            if not self.create_data_backup():
                print("⚠️  Data backup failed, but continuing with rollback...")
                success = False
        
        # Step 2: Stop running executions
        if not self.stop_running_executions():
            print("⚠️  Could not stop all running executions, but continuing...")
            success = False
        
        # Step 3: Perform stack rollback
        if not self.perform_stack_rollback(rollback_type):
            print("❌ Stack rollback failed")
            return False
        
        print("\n🎉 Rollback procedure completed!")
        
        if preserve_data and self.backup_metadata:
            print("\n💾 Data Backup Information:")
            backup_timestamp = list(self.backup_metadata.values())[0]['timestamp']
            backup_bucket = list(self.backup_metadata.values())[0]['bucket']
            print(f"   Timestamp: {backup_timestamp}")
            print(f"   Bucket: {backup_bucket}")
            print(f"   To restore data later, use: --restore-backup {backup_timestamp}")
        
        return success


def main():
    """Main rollback script entry point"""
    parser = argparse.ArgumentParser(
        description='Rollback IAM Identity Center Discovery Solution deployment'
    )
    parser.add_argument(
        '--stack-name', '-s',
        required=True,
        help='CloudFormation stack name'
    )
    parser.add_argument(
        '--region', '-r',
        default='us-east-1',
        help='AWS region (default: us-east-1)'
    )
    parser.add_argument(
        '--rollback-type',
        choices=['update', 'delete'],
        default='update',
        help='Type of rollback to perform (default: update)'
    )
    parser.add_argument(
        '--preserve-data',
        action='store_true',
        default=True,
        help='Create backup of data before rollback (default: true)'
    )
    parser.add_argument(
        '--no-preserve-data',
        action='store_true',
        help='Do not create backup of data before rollback'
    )
    parser.add_argument(
        '--restore-backup',
        help='Restore data from specific backup timestamp'
    )
    parser.add_argument(
        '--list-backups',
        action='store_true',
        help='List available backups'
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='Force rollback without confirmation'
    )
    
    args = parser.parse_args()
    
    # Handle preserve data logic
    preserve_data = args.preserve_data and not args.no_preserve_data
    
    # Initialize rollback manager
    rollback_manager = RollbackManager(
        stack_name=args.stack_name,
        region=args.region
    )
    
    # Handle different actions
    if args.list_backups:
        backups = rollback_manager.list_available_backups()
        if backups:
            print("Available backups:")
            for backup in backups:
                print(f"  {backup}")
        else:
            print("No backups found")
        return
    
    if args.restore_backup:
        success = rollback_manager.restore_data_from_backup(args.restore_backup)
        sys.exit(0 if success else 1)
    
    # Confirm rollback action
    if not args.force:
        print(f"⚠️  This will rollback the stack: {args.stack_name}")
        print(f"   Rollback type: {args.rollback_type}")
        print(f"   Preserve data: {preserve_data}")
        confirm = input("Are you sure you want to proceed? (yes/no): ")
        if confirm.lower() != 'yes':
            print("❌ Rollback cancelled")
            sys.exit(0)
    
    # Perform rollback
    success = rollback_manager.perform_complete_rollback(
        preserve_data=preserve_data,
        rollback_type=args.rollback_type
    )
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()