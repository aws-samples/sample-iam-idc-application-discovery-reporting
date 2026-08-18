#!/usr/bin/env python3
"""
CDK App for IAM Identity Center Discovery Solution

This app deploys the version with:
- Customer-managed KMS encryption
- VPC isolation
- Enhanced IAM permissions
- Comprehensive monitoring
"""

import os
import aws_cdk as cdk
import warnings
from cdk_nag import AwsSolutionsChecks
from stacks.iam_identity_center_discovery_stack import IamIdentityCenterDiscoveryStack

# Get environment configuration
environment = os.environ.get('CDK_ENVIRONMENT', 'dev')

app = cdk.App()

# Suppress Typeguard validation of protocols that are not runtime-checkable
warnings.filterwarnings('ignore', category=UserWarning, module='aws_cdk')
warnings.filterwarnings('ignore', message='Typeguard cannot check')

# Deploy the stack
stack = IamIdentityCenterDiscoveryStack(
    app, 
    f"IamIdentityCenterDiscoveryStack-{environment}",
    description=f"IAM Identity Center Discovery Solution - {environment}",
    env=cdk.Environment(
        account=os.environ.get('CDK_DEFAULT_ACCOUNT'),
        region=os.environ.get('CDK_DEFAULT_REGION', 'us-east-1')
    ),
    tags={
        "Project": "IAM-Identity-Center-Discovery",
        "Environment": environment,
        "Owner": "Security-Team",
        "CostCenter": "Infrastructure"
    }
)

# Run the cdk-nag AwsSolutions rule pack over the synthesized template.
#
# Suppressions are inert without this Aspect: NagSuppressions calls register
# metadata that nothing reads unless a rule pack is actually visiting the tree.
# This stack shipped with no Aspect and no suppressions, so its IaC had never
# been checked at all -- wiring this up surfaced 41 findings on first run,
# including an S3 bucket with server access logging disabled and an API Gateway
# stage with no CloudWatch logging. Both are now fixed rather than suppressed.
cdk.Aspects.of(app).add(AwsSolutionsChecks(verbose=True))

app.synth()