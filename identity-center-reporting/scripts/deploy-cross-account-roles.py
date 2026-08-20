#!/usr/bin/env python3
"""
Cross-Account Role Deployment Script for IAM Identity Center Discovery Solution
Deploys the necessary IAM roles in member accounts for cross-account discovery
"""

import argparse
import json
from pathlib import Path
import yaml
import re
import boto3
import time
from typing import List, Dict, Optional, Tuple
from botocore.exceptions import ClientError
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed



def _resolve_cfn_shorthand(text: str) -> str:
    """
    Turn the CloudFormation short forms this template uses into plain YAML.

    The template is authored for CloudFormation, so it uses !Sub and !GetAtt.
    yaml.safe_load rejects those tags, and registering a constructor that returns
    None would silently drop the values. Rewriting !Sub to its literal string and
    !GetAtt to Fn::GetAtt keeps the meaning, and the only !Sub in the file is the
    account-ID substitution this script performs itself.
    """
    text = re.sub(r"!Sub\s+'([^']*)'", r'"\1"', text)
    text = re.sub(r'!GetAtt\s+([A-Za-z0-9.]+)', r'{"Fn::GetAtt": "\1"}', text)
    text = re.sub(r'!Ref\s+([A-Za-z0-9]+)', r'{"Ref": "\1"}', text)
    return text


class CrossAccountRoleDeployer:
    """Deploys cross-account IAM roles to member accounts"""
    
    def __init__(self, profile_name: str = None, management_account_id: str = None, region: str = 'us-east-1', 
                 assume_role_name: str = 'OrganizationAccountAccessRole'):
        self.region = region
        self.profile_name = profile_name
        self.assume_role_name = assume_role_name
        
        # Initialize AWS clients with the specified profile or default credentials
        if profile_name:
            print(f"🔐 Using AWS profile: {profile_name}")
            self.session = boto3.Session(profile_name=profile_name, region_name=region)
        else:
            print(f"🔐 Using default AWS credentials")
            self.session = boto3.Session(region_name=region)
        self.organizations = self.session.client('organizations')
        self.sts = self.session.client('sts')
        
        # Get current account from the profile
        current_account = self.sts.get_caller_identity()['Account']
        print(f"📍 Current account (from {profile_name} profile): {current_account}")
        
        # Use provided management_account_id or auto-detect from current account
        if management_account_id:
            self.management_account_id = management_account_id
            print(f"📋 Using provided management account ID: {management_account_id}")
        else:
            self.management_account_id = current_account
            print(f"📋 Auto-detected management account ID: {current_account}")
        
        # Verify we have access to Organizations API
        try:
            org_info = self.organizations.describe_organization()
            org_id = org_info['Organization']['Id']
            org_master_account = org_info['Organization']['MasterAccountId']
            print(f"✅ Organizations API access confirmed")
            print(f"   Organization ID: {org_id}")
            print(f"   Master Account: {org_master_account}")
            print(f"   Assume Role Name: {self.assume_role_name}")
            
            if org_master_account != self.management_account_id:
                print(f"⚠️  WARNING: Management account {self.management_account_id} differs from Organization master account {org_master_account}")
        except ClientError as e:
            raise ValueError(f"Current account {current_account} does not have Organizations API access: {e}")
    
    def get_organization_accounts(self) -> List[Dict]:
        """Get all accounts in the organization"""
        try:
            accounts = []
            paginator = self.organizations.get_paginator('list_accounts')
            
            for page in paginator.paginate():
                for account in page['Accounts']:
                    if account['Status'] == 'ACTIVE':
                        accounts.append(account)
            
            print(f"Found {len(accounts)} active accounts in organization")
            return accounts
            
        except ClientError as e:
            print(f"Error listing organization accounts: {e}")
            return []
    
    def create_cloudformation_template(self, external_id: str) -> Dict:
        """
        Build the cross-account role template.

        external_id is required, with no default. It used to default to the
        literal string 'iam-identity-center-discovery', which is published in this
        repository -- an ExternalId only prevents a third party from having a role
        act on their behalf while the value is unknown to them, so a default that
        ships in a sample protects nothing. It must match the
        CrossAccountExternalId parameter given to the reporting stack.
        """
        # Values that have appeared in this repository, and so are known to
        # everyone who has read it. A length check alone does not catch them:
        # the original hardcoded value is 29 characters.
        PUBLISHED_VALUES = {
            'iam-identity-center-discovery',
            'iam-identity-center-cross-account-discovery-role',
        }

        if not external_id or len(external_id) < 16:
            raise ValueError(
                "external_id is required and must be at least 16 characters. "
                "Generate one (uuidgen works) and pass the same value to the "
                "reporting stack as --parameters CrossAccountExternalId=<value>."
            )
        if external_id in PUBLISHED_VALUES:
            raise ValueError(
                f"external_id {external_id!r} has been published in this "
                f"repository, so it is known to anyone who has read it and "
                f"provides no confused-deputy protection. Generate a unique value."
            )

        
        # Read the template from scripts/cross-account-role-template.yaml rather
        # than embedding a second copy here.
        #
        # There used to be a duplicate of the whole template in this function.
        # Two sources of truth for one role is a drift hazard on its own -- and it
        # bit immediately: converting the YAML's inline policy to a managed policy
        # (cfn-guard IAM_NO_INLINE_POLICY_CHECK) would have left this copy still
        # deploying an inline policy, so the fix would have been cosmetic while the
        # roles that actually get created stayed unchanged.
        template_path = Path(__file__).parent / 'cross-account-role-template.yaml'
        with open(template_path) as handle:
            template = yaml.safe_load(_resolve_cfn_shorthand(handle.read()))

        # The YAML takes the deploying account as a parameter; this script knows it
        # already and deploys with a plain template body, so substitute it here and
        # drop the parameter.
        rendered = json.dumps(template)
        rendered = rendered.replace(
            '${SolutionDeployedAccountId}', self.management_account_id
        )
        template = json.loads(rendered)
        template.pop('Parameters', None)

        trust = (template['Resources']['CrossAccountDiscoveryRole']['Properties']
                 ['AssumeRolePolicyDocument']['Statement'][0])
        trust['Condition']['StringEquals']['sts:ExternalId'] = external_id

        return template
    
    def assume_role_in_account(self, account_id: str, role_name: str = None) -> Optional[boto3.Session]:
        """Assume role in member account"""
        try:
            # Use provided role_name or fall back to instance default
            role_to_assume = role_name if role_name else self.assume_role_name
            role_arn = f"arn:aws:iam::{account_id}:role/{role_to_assume}"
            
            print(f"     🔐 Attempting to assume role: {role_arn}")

            # No ExternalId here. This assumes the *deployment* role
            # (OrganizationAccountAccessRole or equivalent) in order to create the
            # discovery role; it is not the discovery role itself. Organization
            # admin roles are trusted by account, not by ExternalId, so sending the
            # discovery ExternalId conflated two unrelated trust relationships --
            # harmless only because a trust policy without an sts:ExternalId
            # condition ignores the value.
            response = self.sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"IAMIdentityCenterDiscovery-{account_id}"
            )
            
            credentials = response['Credentials']
            
            session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken'],
                region_name=self.region
            )
            
            return session
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            print(f"     ❌ Error assuming role in account {account_id}")
            print(f"        Role ARN: {role_arn}")
            print(f"        Error Code: {error_code}")
            print(f"        Error Message: {error_message}")
            return None
    
    def deploy_role_to_account(self, account_id: str, account_name: str, template: Dict, 
                              stack_name: str = 'iam-identity-center-cross-account-role') -> Tuple[str, bool, str]:
        """Deploy cross-account role to a single account"""
        
        # Skip management account
        if account_id == self.management_account_id:
            print(f"   Skipping management account: {account_name} ({account_id})")
            return account_id, True, "Skipped (management account)"
        
        print(f"   Deploying to account: {account_name} ({account_id})")
        
        try:
            # Assume role in member account
            member_session = self.assume_role_in_account(account_id)
            if not member_session:
                return account_id, False, "Failed to assume role"
            
            cloudformation = member_session.client('cloudformation')
            
            # Check if stack already exists
            try:
                response = cloudformation.describe_stacks(StackName=stack_name)
                stack_exists = True
                current_status = response['Stacks'][0]['StackStatus']
            except ClientError as e:
                if e.response['Error']['Code'] == 'ValidationError':
                    stack_exists = False
                    current_status = None
                else:
                    return account_id, False, f"Error checking stack: {e}"
            
            # Deploy or update stack
            template_body = json.dumps(template, indent=2)
            
            if stack_exists:
                if current_status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                    print(f"     Stack already exists and is up to date")
                    return account_id, True, "Already deployed"
                elif current_status in ['UPDATE_IN_PROGRESS', 'CREATE_IN_PROGRESS']:
                    print(f"     Stack deployment in progress, skipping")
                    return account_id, True, "Deployment in progress"
                else:
                    # Update stack
                    cloudformation.update_stack(
                        StackName=stack_name,
                        TemplateBody=template_body,
                        Parameters=[
                            {
                                'ParameterKey': 'ManagementAccountId',
                                'ParameterValue': self.management_account_id
                            }
                        ],
                        Capabilities=['CAPABILITY_NAMED_IAM'],
                        Tags=[
                            {
                                'Key': 'Purpose',
                                'Value': 'IAMIdentityCenterDiscovery'
                            },
                            {
                                'Key': 'ManagedBy',
                                'Value': 'CrossAccountRoleDeployer'
                            }
                        ]
                    )
                    operation = "update"
            else:
                # Create stack
                cloudformation.create_stack(
                    StackName=stack_name,
                    TemplateBody=template_body,
                    Parameters=[
                        {
                            'ParameterKey': 'ManagementAccountId',
                            'ParameterValue': self.management_account_id
                        }
                    ],
                    Capabilities=['CAPABILITY_NAMED_IAM'],
                    Tags=[
                        {
                            'Key': 'Purpose',
                            'Value': 'IAMIdentityCenterDiscovery'
                        },
                        {
                            'Key': 'ManagedBy',
                            'Value': 'CrossAccountRoleDeployer'
                        }
                    ]
                )
                operation = "create"
            
            # Wait for stack operation to complete
            if operation == "create":
                waiter = cloudformation.get_waiter('stack_create_complete')
            else:
                waiter = cloudformation.get_waiter('stack_update_complete')
            
            waiter.wait(
                StackName=stack_name,
                WaiterConfig={
                    'Delay': 15,
                    'MaxAttempts': 40  # 10 minutes max
                }
            )
            
            print(f"     ✅ Successfully deployed role to {account_name}")
            return account_id, True, f"Successfully {operation}d"
            
        except ClientError as e:
            error_msg = f"CloudFormation error: {e}"
            print(f"     ❌ Failed to deploy to {account_name}: {error_msg}")
            return account_id, False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            print(f"     ❌ Failed to deploy to {account_name}: {error_msg}")
            return account_id, False, error_msg
    
    def deploy_to_all_accounts(self, accounts: List[Dict], external_id: str,
                               max_workers: int = 5) -> Dict[str, Tuple[bool, str]]:
        """Deploy cross-account roles to all accounts in parallel"""

        template = self.create_cloudformation_template(external_id)
        results = {}
        
        # Filter out management account
        member_accounts = [acc for acc in accounts if acc['Id'] != self.management_account_id]
        skipped_count = len(accounts) - len(member_accounts)
        
        if skipped_count > 0:
            print(f"ℹ️  Skipping {skipped_count} management account(s)")
        
        print(f"🚀 Deploying cross-account roles to {len(member_accounts)} member accounts...")
        print(f"   Using {max_workers} parallel workers")
        print()
        
        # Add management account to results as skipped
        if skipped_count > 0:
            for account in accounts:
                if account['Id'] == self.management_account_id:
                    results[account['Id']] = (True, "Skipped (management account)")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit deployment tasks only for member accounts
            future_to_account = {
                executor.submit(
                    self.deploy_role_to_account,
                    account['Id'],
                    account['Name'],
                    template
                ): account for account in member_accounts
            }
            
            # Collect results
            for future in as_completed(future_to_account):
                account = future_to_account[future]
                try:
                    account_id, success, message = future.result()
                    results[account_id] = (success, message)
                except Exception as e:
                    results[account['Id']] = (False, f"Execution error: {e}")
        
        return results
    
    def validate_role_deployment(self, account_id: str, external_id: str,
                                 role_name: str = 'iam-identity-center-cross-account-discovery-role') -> bool:
        """
        Validate that the cross-account role was deployed correctly.

        external_id must be the same value passed to create_cloudformation_template:
        this assumes the discovery role itself, whose trust policy carries an
        sts:ExternalId condition, so validating with any other value reports a
        correctly-deployed role as broken.
        """

        try:
            # Try to assume the role
            role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            print(f"     🔐 Attempting to assume role: {role_arn}")

            response = self.sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"ValidationTest-{account_id}",
                ExternalId=external_id
            )
            
            assumed_role_id = response['AssumedRoleUser']['AssumedRoleId']
            assumed_role_arn = response['AssumedRoleUser']['Arn']
            print(f"     ✅ Successfully assumed role")
            print(f"        Role ID: {assumed_role_id}")
            print(f"        Role ARN: {assumed_role_arn}")
            
            # Test the assumed role has the right permissions
            test_session = boto3.Session(
                aws_access_key_id=response['Credentials']['AccessKeyId'],
                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                aws_session_token=response['Credentials']['SessionToken'],
                region_name=self.region
            )
            
            print(f"     🔍 Testing permissions with assumed role...")
            
            # Test SSO Admin permissions
            sso_admin = test_session.client('sso-admin')
            print(f"     📞 Calling sso:ListInstances...")
            
            instances_response = sso_admin.list_instances()
            instance_count = len(instances_response.get('Instances', []))
            print(f"     ✅ sso:ListInstances succeeded (found {instance_count} instances)")
            
            # Test Identity Store permissions if we have an instance
            if instance_count > 0:
                identity_store_id = instances_response['Instances'][0].get('IdentityStoreId')
                if identity_store_id:
                    print(f"     📞 Testing identitystore permissions with ID: {identity_store_id}")
                    identitystore = test_session.client('identitystore')
                    
                    try:
                        # Try to list users (may return empty but should not error on permissions)
                        identitystore.list_users(
                            IdentityStoreId=identity_store_id,
                            MaxResults=1
                        )
                        print(f"     ✅ identitystore:ListUsers succeeded")
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'AccessDeniedException':
                            print(f"     ⚠️  identitystore:ListUsers access denied: {e}")
                        else:
                            print(f"     ℹ️  identitystore:ListUsers returned: {e.response['Error']['Code']}")
            
            print(f"     ✅ Validation successful for account {account_id}")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            print(f"     ❌ Validation failed for account {account_id}")
            print(f"        Error Code: {error_code}")
            print(f"        Error Message: {error_message}")
            return False
        except Exception as e:
            print(f"     ❌ Validation error for account {account_id}: {e}")
            return False
    
    def validate_all_deployments(self, results: Dict[str, Tuple[bool, str]]) -> Dict[str, bool]:
        """Validate all successful deployments"""
        
        successful_accounts = [
            account_id for account_id, (success, _) in results.items() 
            if success and account_id != self.management_account_id
        ]
        
        if not successful_accounts:
            print("No successful deployments to validate")
            return {}
        
        print(f"🔍 Validating {len(successful_accounts)} successful deployments...")
        
        validation_results = {}
        
        for account_id in successful_accounts:
            print(f"   Validating account: {account_id}")
            validation_results[account_id] = self.validate_role_deployment(account_id)
        
        return validation_results
    
    def print_deployment_summary(self, accounts: List[Dict], results: Dict[str, Tuple[bool, str]], 
                                validation_results: Dict[str, bool] = None):
        """Print deployment summary"""
        
        print("\n" + "="*80)
        print("CROSS-ACCOUNT ROLE DEPLOYMENT SUMMARY")
        print("="*80)
        
        successful = sum(1 for success, _ in results.values() if success)
        failed = len(results) - successful
        
        print(f"Total Accounts: {len(accounts)}")
        print(f"✅ Successful: {successful}")
        print(f"❌ Failed: {failed}")
        
        if validation_results:
            validated = sum(1 for valid in validation_results.values() if valid)
            print(f"🔍 Validated: {validated}/{len(validation_results)}")
        
        # Show failed deployments
        if failed > 0:
            print("\nFAILED DEPLOYMENTS:")
            account_map = {acc['Id']: acc['Name'] for acc in accounts}
            
            for account_id, (success, message) in results.items():
                if not success:
                    account_name = account_map.get(account_id, 'Unknown')
                    print(f"  ❌ {account_name} ({account_id}): {message}")
        
        # Show validation failures
        if validation_results:
            validation_failures = [
                account_id for account_id, valid in validation_results.items() 
                if not valid
            ]
            
            if validation_failures:
                print("\nVALIDATION FAILURES:")
                account_map = {acc['Id']: acc['Name'] for acc in accounts}
                
                for account_id in validation_failures:
                    account_name = account_map.get(account_id, 'Unknown')
                    print(f"  ❌ {account_name} ({account_id}): Role validation failed")
        
        print("\nNEXT STEPS:")
        print("1. Review any failed deployments and resolve issues")
        print("2. Update the main discovery stack with the deployed role ARNs")
        print("3. Test cross-account discovery functionality")
        print("4. Monitor CloudWatch logs for any access issues")
        
        print("="*80)
    
    def remove_roles_from_accounts(self, accounts: List[Dict], stack_name: str = 'iam-identity-center-cross-account-role') -> Dict[str, Tuple[bool, str]]:
        """Remove cross-account roles from all accounts"""
        
        # Filter out management account
        member_accounts = [acc for acc in accounts if acc['Id'] != self.management_account_id]
        skipped_count = len(accounts) - len(member_accounts)
        
        if skipped_count > 0:
            print(f"ℹ️  Skipping {skipped_count} management account(s)")
        
        print(f"🗑️  Removing cross-account roles from {len(member_accounts)} member accounts...")
        
        results = {}
        
        # Add management account to results as skipped
        for account in accounts:
            if account['Id'] == self.management_account_id:
                results[account['Id']] = (True, "Skipped (management account)")
        
        for account in member_accounts:
            account_id = account['Id']
            account_name = account['Name']
            
            print(f"   Removing from account: {account_name} ({account_id})")
            
            try:
                # Assume role in member account
                member_session = self.assume_role_in_account(account_id)
                if not member_session:
                    results[account_id] = (False, "Failed to assume role")
                    continue
                
                cloudformation = member_session.client('cloudformation')
                
                # Check if stack exists
                try:
                    cloudformation.describe_stacks(StackName=stack_name)
                    stack_exists = True
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ValidationError':
                        stack_exists = False
                    else:
                        results[account_id] = (False, f"Error checking stack: {e}")
                        continue
                
                if not stack_exists:
                    results[account_id] = (True, "Stack not found (already removed)")
                    continue
                
                # Delete stack
                cloudformation.delete_stack(StackName=stack_name)
                
                # Wait for deletion to complete
                waiter = cloudformation.get_waiter('stack_delete_complete')
                waiter.wait(
                    StackName=stack_name,
                    WaiterConfig={
                        'Delay': 15,
                        'MaxAttempts': 40
                    }
                )
                
                print(f"     ✅ Successfully removed role from {account_name}")
                results[account_id] = (True, "Successfully removed")
                
            except ClientError as e:
                error_msg = f"CloudFormation error: {e}"
                print(f"     ❌ Failed to remove from {account_name}: {error_msg}")
                results[account_id] = (False, error_msg)
            except Exception as e:
                error_msg = f"Unexpected error: {e}"
                print(f"     ❌ Failed to remove from {account_name}: {error_msg}")
                results[account_id] = (False, error_msg)
        
        return results


def main():
    """Main script entry point"""
    parser = argparse.ArgumentParser(
        description='Deploy cross-account IAM roles for IAM Identity Center Discovery'
    )
    parser.add_argument(
        '--external-id',
        required=True,
        help=(
            'REQUIRED. Unique ExternalId for the cross-account trust policy. Must '
            'match the CrossAccountExternalId parameter given to the reporting '
            'stack. Generate your own (uuidgen); do not reuse a published value, '
            'because an ExternalId only works while it is not public knowledge.'
        )
    )
    parser.add_argument(
        '--profile', '-p',
        required=False,
        help='AWS profile name to use (optional, uses default credentials if not specified)'
    )
    parser.add_argument(
        '--management-account-id', '-m',
        required=False,
        help='AWS Account ID that the member-account roles will TRUST — the account '
             'where the discovery solution is deployed (the delegated admin account in '
             'the recommended setup). Default: auto-detect from the current profile, '
             'which is correct when you run this script from the deployment account.'
    )
    parser.add_argument(
        '--region', '-r',
        default='us-east-1',
        help='AWS region (default: us-east-1)'
    )
    parser.add_argument(
        '--assume-role-name',
        default='OrganizationAccountAccessRole',
        help='Name of the role to assume in member accounts (default: OrganizationAccountAccessRole)'
    )
    parser.add_argument(
        '--action',
        choices=['deploy', 'validate', 'remove'],
        default='deploy',
        help='Action to perform (default: deploy)'
    )
    parser.add_argument(
        '--max-workers',
        type=int,
        default=5,
        help='Maximum number of parallel workers (default: 5)'
    )
    parser.add_argument(
        '--accounts',
        nargs='+',
        help='Specific account IDs to target (default: all organization accounts)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be done without making changes'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize deployer
        deployer = CrossAccountRoleDeployer(
            profile_name=args.profile,
            management_account_id=args.management_account_id,
            region=args.region,
            assume_role_name=args.assume_role_name
        )
        
        # Get target accounts
        if args.accounts:
            # Use specific accounts
            accounts = []
            for account_id in args.accounts:
                accounts.append({
                    'Id': account_id,
                    'Name': f'Account-{account_id}',
                    'Status': 'ACTIVE'
                })
        else:
            # Get all organization accounts
            accounts = deployer.get_organization_accounts()
        
        if not accounts:
            print("No accounts found to process")
            sys.exit(1)
        
        print(f"Target accounts: {len(accounts)}")
        for account in accounts:
            print(f"  - {account['Name']} ({account['Id']})")
        print()
        
        if args.dry_run:
            print("DRY RUN MODE - No changes will be made")
            template = deployer.create_cloudformation_template(args.external_id)
            print("CloudFormation template that would be deployed:")
            print(json.dumps(template, indent=2))
            sys.exit(0)
        
        # Perform requested action
        if args.action == 'deploy':
            results = deployer.deploy_to_all_accounts(accounts, args.external_id, args.max_workers)
            validation_results = deployer.validate_all_deployments(results, args.external_id)
            deployer.print_deployment_summary(accounts, results, validation_results)
            
            # Exit with error code if any deployments failed
            failed_count = sum(1 for success, _ in results.values() if not success)
            sys.exit(1 if failed_count > 0 else 0)
            
        elif args.action == 'validate':
            results = {acc['Id']: (True, "Validation target") for acc in accounts}
            validation_results = deployer.validate_all_deployments(results, args.external_id)
            deployer.print_deployment_summary(accounts, results, validation_results)
            
            # Exit with error code if any validations failed
            failed_validations = sum(1 for valid in validation_results.values() if not valid)
            sys.exit(1 if failed_validations > 0 else 0)
            
        elif args.action == 'remove':
            results = deployer.remove_roles_from_accounts(accounts)
            deployer.print_deployment_summary(accounts, results)
            
            # Exit with error code if any removals failed
            failed_count = sum(1 for success, _ in results.values() if not success)
            sys.exit(1 if failed_count > 0 else 0)
        
    except Exception as e:
        print(f"❌ Script error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()