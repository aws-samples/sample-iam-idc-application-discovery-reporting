# IAM Identity Center Discovery - Utility Scripts

This directory contains utility scripts for managing and maintaining the IAM Identity Center Discovery Solution.

## Scripts Overview

### deploy-cross-account-roles.py
**Purpose**: Deploy IAM roles in member accounts for cross-account discovery

**Features**:
- Creates CloudFormation templates for cross-account roles
- Deploys roles to all organization accounts in parallel
- Validates role deployment and permissions
- Supports removal of roles
- **Important**: If using a delegated admin account for IAM Identity Center, deploy the cross-account role in that account as well

**Usage**:
```bash
# Deploy roles to all organization accounts
python scripts/deploy-cross-account-roles.py --management-account-id 123456789012

# Deploy to specific accounts (including delegated admin account)
python scripts/deploy-cross-account-roles.py --management-account-id 123456789012 --accounts 111111111111 222222222222

# Validate existing deployments
python scripts/deploy-cross-account-roles.py --management-account-id 123456789012 --action validate

# Remove roles from all accounts
python scripts/deploy-cross-account-roles.py --management-account-id 123456789012 --action remove
```

**Delegated Admin Account Setup**:
If your IAM Identity Center is managed by a delegated administrator account:
1. Deploy the cross-account role in the delegated admin account
2. Configure the `DelegatedAdminAccountId` parameter during solution deployment
3. The solution will automatically assume the role when accessing Identity Center

```bash
# Example: Deploy role to delegated admin account
python scripts/deploy-cross-account-roles.py \
  --management-account-id 123456789012 \
  --accounts 999888777666  # Your delegated admin account ID
```

### post-deployment/rollback-procedures.py
**Purpose**: Provide safe rollback mechanisms with data preservation

**Features**:
- Creates backups of DynamoDB data and S3 contents
- Stops running Step Functions executions
- Performs CloudFormation stack rollback
- Restores data from backups

**Usage**:
```bash
# Perform rollback with data backup
python scripts/post-deployment/rollback-procedures.py --stack-name IamIdentityCenterDiscoveryStack-dev

# Rollback without preserving data
python scripts/post-deployment/rollback-procedures.py --stack-name IamIdentityCenterDiscoveryStack-dev --no-preserve-data

# List available backups
python scripts/post-deployment/rollback-procedures.py --stack-name IamIdentityCenterDiscoveryStack-dev --list-backups

# Restore from specific backup
python scripts/post-deployment/rollback-procedures.py --stack-name IamIdentityCenterDiscoveryStack-dev --restore-backup 20241201-143022
```

## Prerequisites

All scripts require:
- Python 3.8+
- boto3 library
- Appropriate AWS credentials configured
- Necessary AWS permissions for the resources they manage

## Integration with Main Solution

These scripts are designed to work alongside the main IAM Identity Center Discovery Solution:

- **deploy-cross-account-roles.py**: Should be run before deploying the main stack in multi-account environments
- **post-deployment/rollback-procedures.py**: Emergency rollback tool for production deployments
- **post-deployment/start_manual_discovery.py**: Utility to manually trigger discovery workflows

## Security Considerations

- All scripts follow AWS security best practices
- Data backups are encrypted and versioned
- Cross-account roles use external IDs for additional security

## Support

For issues or questions about these scripts, refer to the main project documentation or create an issue in the project repository.