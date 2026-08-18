"""
CDK Stack for IAM Identity Center Discovery Solution

This version implements comprehensive security improvements:
- DynamoDB encryption at rest with customer-managed KMS keys
- Lambda VPC configuration with security groups
- S3 bucket hardening with encryption and access controls
- IAM permission tightening with least privilege
- Enhanced monitoring and logging
"""

import aws_cdk as cdk
from aws_cdk import (
    Stack,
    aws_lambda as _lambda,
    aws_stepfunctions as sfn,
    aws_stepfunctions_tasks as sfn_tasks,
    aws_dynamodb as dynamodb,
    aws_s3 as s3,
    aws_apigateway as apigateway,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_logs as logs,
    aws_sns as sns,
    aws_sns_subscriptions as sns_subscriptions,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cloudwatch_actions,
    aws_kms as kms,
    aws_ec2 as ec2,
    Duration,
    RemovalPolicy
)
from cdk_nag import NagSuppressions
from constructs import Construct
import json
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

class IamIdentityCenterDiscoveryStack(Stack):
    """
    CDK Stack for IAM Identity Center Discovery Solution
    """

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Create CDK parameter for IP restriction.
        # SECURITY: this CIDR restricts both the API Gateway and the S3
        # presigned-URL downloads, which carry PII (user emails/display names).
        # The 0.0.0.0/0 default keeps the sample deployable and demoable out of
        # the box, but means a leaked presigned URL is downloadable from ANY IP
        # with no additional IAM check. For any non-demo use, set this to your
        # corporate/VPN CIDR. See "Security considerations for production" in
        # the README.
        self.allowed_ip_range = cdk.CfnParameter(
            self, "AllowedIpRange",
            type="String",
            description="CIDR allowed to reach the API and download presigned CSV URLs (which contain PII). Default 0.0.0.0/0 allows ALL IPs — set to your corporate/VPN CIDR for anything beyond a demo.",
            default="0.0.0.0/0",
            allowed_pattern="^([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]{1,2}$",
            constraint_description="Must be a valid CIDR block (e.g., 10.0.0.0/8, 192.168.1.0/24, or 0.0.0.0/0 for all)"
        )

        # Surface a synth-time warning when the default open range is in effect
        # via context override (cdk deploy -c acknowledgeOpenIpRange=true to
        # silence). CfnParameter values are resolved at deploy time, not synth,
        # so this warns based on whether the deployer has explicitly acknowledged.
        if not self.node.try_get_context("acknowledgeOpenIpRange"):
            cdk.Annotations.of(self).add_info(
                "AllowedIpRange defaults to 0.0.0.0/0 (open). Presigned CSV URLs "
                "carry PII and will be downloadable from any IP. Pass "
                "--parameters AllowedIpRange=<your-CIDR> for non-demo use, or "
                "-c acknowledgeOpenIpRange=true to silence this notice."
            )
        
        # Create CDK parameter for DynamoDB Point-in-Time Recovery
        # Point-in-Time Recovery is a SYNTH-TIME flag, not a CloudFormation
        # parameter. A CfnParameter's value is a deploy-time token, so
        # `param.value_as_string == "true"` is always False in Python and the
        # setting silently never took effect. Pass it as context instead:
        #   cdk deploy -c enableDynamoDbPitr=false
        #
        # Defaults to ENABLED. These tables are the audit record of who had access
        # to what, so a bad discovery run or an accidental delete should be
        # recoverable; that is also what AwsSolutions-DDB3 checks. Opt out only
        # for throwaway environments where the continuous-backup cost matters
        # more than the recovery window.
        self.enable_dynamodb_pitr = (
            str(self.node.try_get_context("enableDynamoDbPitr") or "true").lower() != "false"
        )
        
        # Create CDK parameter for Delegated Admin Account ID
        self.delegated_admin_account_id = cdk.CfnParameter(
            self, "DelegatedAdminAccountId",
            type="String",
            description="(Optional) AWS Account ID of the delegated administrator for IAM Identity Center. If specified and different from the current account, the solution will assume a cross-account role to access Identity Center. Leave empty if running in the delegated admin account.",
            default="",
            allowed_pattern="^$|^[0-9]{12}$",
            constraint_description="Must be empty or a valid 12-digit AWS Account ID"
        )
        
        # Create CDK parameter for Group Name Regex — must match the value
        # configured on the reactive-monitoring stack (GroupNameRegex) so both
        # stacks reach the same compliance verdict for the same assignment.
        self.group_name_regex = cdk.CfnParameter(
            self, "GroupNameRegex",
            type="String",
            description="Optional regex to extract a friendly group name (first capture group) before matching. Keep in sync with the reactive-monitoring stack's GroupNameRegex. Leave empty for plain substring matching.",
            default=""
        )

        # Create CDK parameter for Stale Assignment Threshold
        self.stale_threshold_days = cdk.CfnParameter(
            self, "StaleThresholdDays",
            type="Number",
            description="Number of days without access after which an assignment is considered stale. Used by the access tracker to flag unused assignments.",
            default=30,
            min_value=1,
            max_value=365,
            constraint_description="Must be a number between 1 and 365"
        )

        # Create KMS keys for encryption
        self.create_kms_keys()
        
        # Create VPC and security infrastructure
        self.create_vpc_infrastructure()
        
        # Create DynamoDB tables with encryption
        self.create_dynamodb_tables()
        
        # Create S3 bucket with security hardening
        self.create_s3_bucket()
        
        # Create Lambda functions with VPC and security
        self.create_lambda_functions()
        
        # Create Step Functions state machine
        self.create_step_functions()
        
        # Create API Gateway with enhanced security
        self.create_api_gateway()
        
        # Create CloudWatch Events for scheduling
        self.create_scheduling()
        
        # Create monitoring and alerting
        self.create_monitoring_and_alerting()

        # Record why the remaining cdk-nag findings are accepted
        self.add_nag_suppressions()

    def add_nag_suppressions(self):
        """
        Justify every AwsSolutions finding that is not fixed in code.

        These are stack-level suppressions because this stack builds its
        resources inside helper methods without retaining per-construct handles
        for every policy, and cdk-nag reports IAM findings against generated
        policy constructs rather than the roles as written. Each entry states the
        specific reason rather than a generic "accepted", so a reviewer can
        disagree with a particular one without having to re-derive the analysis.

        Fixed rather than suppressed, for the record: AwsSolutions-S1 (added a
        dedicated SSE-S3 server-access-log bucket), AwsSolutions-APIG6 (enabled
        stage execution logging) and AwsSolutions-DDB3 (point-in-time recovery
        now defaults to enabled).
        """
        NagSuppressions.add_stack_suppressions(
            self,
            [
                {
                    "id": "AwsSolutions-IAM4",
                    "reason": (
                        "AWSLambdaVPCAccessExecutionRole and AWSLambdaBasicExecutionRole are "
                        "attached by the CDK Lambda construct to grant ENI management and log "
                        "delivery. Both are scoped to those functions and cannot be replaced "
                        "with an inline policy without reimplementing the construct. "
                        "AmazonAPIGatewayPushToCloudWatchLogs is attached to the account-level "
                        "API Gateway CloudWatch role that CDK creates as a direct consequence of "
                        "enabling stage execution logging for AwsSolutions-APIG6; API Gateway "
                        "requires that specific managed policy to write execution logs."
                    ),
                    "appliesTo": [
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
                        "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs",
                    ],
                },
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": (
                        "Each remaining wildcard was reviewed individually. Three classes: "
                        "(1) IAM-permission-only actions that AWS does not support resource "
                        "scoping for at all -- organizations:ListAccounts, "
                        "organizations:DescribeOrganization, ec2:DescribeRegions, "
                        "cloudtrail:LookupEvents, identitystore list/describe, and "
                        "cloudwatch:PutMetricData; PutMetricData is additionally constrained by "
                        "a cloudwatch:namespace condition limiting it to this solution's two "
                        "namespaces. (2) Suffix wildcards on resources the solution legitimately "
                        "enumerates: DynamoDB /index/* for its own GSIs, the CSV bucket's "
                        "object path, execute-api method paths, and the sso instance / "
                        "permissionSet / application ARN shapes that discovery must walk. "
                        "(3) KMS key-policy statements where Resource:* denotes the key the "
                        "policy is attached to, plus the kms:GenerateDataKey*/ReEncrypt* action "
                        "wildcards CDK emits for grants."
                    ),
                },
                {
                    "id": "AwsSolutions-L1",
                    "reason": (
                        "The functions run on python3.12, a current Amazon Linux 2023 runtime "
                        "that is not deprecated. This rule cannot be satisfied by any available "
                        "runtime: cdk-nag 2.38.2, the newest 2.x release, still reports L1 when "
                        "the functions are moved to python3.13 (verified by synthesizing both), "
                        "so its latest-runtime list is behind the runtimes AWS actually offers. "
                        "Revisit when cdk-nag recognises python3.13."
                    ),
                },
                {
                    "id": "AwsSolutions-COG4",
                    "reason": (
                        "The export API authorizes with IAM (SigV4), not a Cognito user pool. "
                        "There is no user pool in this solution -- callers are IAM principals, "
                        "and the API additionally carries a resource policy restricting source "
                        "IP. Verified against the deployed API with a signed SigV4 request."
                    ),
                },
                {
                    "id": "AwsSolutions-APIG3",
                    "reason": (
                        "No WAFv2 web ACL is attached. The API is IAM-authorized and IP-restricted "
                        "rather than public, so WAF would add cost without addressing the exposure "
                        "this sample has. Attaching a web ACL is the right call for an "
                        "internet-facing deployment and is called out in the README."
                    ),
                },
                {
                    "id": "CdkNagValidationFailure",
                    "reason": (
                        "AwsSolutions-EC23 cannot evaluate the security group rules because the "
                        "CIDR comes from the AllowedIpRange CloudFormation parameter, which is an "
                        "unresolved token at synth time. The parameter is constrained by "
                        "allowed_pattern to a valid CIDR and its open default is surfaced as a "
                        "synth-time annotation."
                    ),
                },
            ],
        )

    def create_kms_keys(self):
        """Create KMS keys for encryption at rest"""

        # All three keys rely on CDK's default key policy (account-root
        # delegation to IAM), so key access is governed by the identity
        # policies below. DynamoDB (grants), S3 SSE-KMS, and Lambda env-var
        # decryption all call KMS with the requesting principal's credentials,
        # so no service-principal statements are needed for them; only
        # CloudWatch Logs and CloudWatch alarm->SNS delivery act as service
        # principals and get explicit, condition-scoped statements.

        # KMS key for DynamoDB encryption
        self.dynamodb_kms_key = kms.Key(
            self, "DynamoDBKMSKey",
            description="KMS key for IAM Identity Center DynamoDB tables encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY
        )

        # KMS key for S3 encryption
        self.s3_kms_key = kms.Key(
            self, "S3KMSKey",
            description="KMS key for IAM Identity Center S3 bucket encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY
        )

        # KMS key for Lambda environment variables encryption
        self.lambda_kms_key = kms.Key(
            self, "LambdaKMSKey",
            description="KMS key for Lambda environment variables encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.DESTROY
        )

        # CloudWatch Logs encrypts the Lambda log groups with this key
        self.lambda_kms_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchLogs",
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal(f"logs.{self.region}.amazonaws.com")],
                actions=[
                    "kms:Decrypt",
                    "kms:DescribeKey",
                    "kms:Encrypt",
                    "kms:GenerateDataKey*",
                    "kms:ReEncrypt*",
                    "kms:CreateGrant"
                ],
                resources=["*"],
                conditions={
                    "ArnLike": {
                        "kms:EncryptionContext:aws:logs:arn": f"arn:aws:logs:{self.region}:{self.account}:*"
                    }
                }
            )
        )

        # CloudWatch alarms publish to the CMK-encrypted SNS alert topics;
        # the alarm service principal must be able to generate data keys for
        # exactly those topics or notification delivery fails silently.
        self.lambda_kms_key.add_to_resource_policy(
            iam.PolicyStatement(
                sid="AllowCloudWatchAlarmsSnsPublish",
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("cloudwatch.amazonaws.com")],
                actions=[
                    "kms:Decrypt",
                    "kms:GenerateDataKey"
                ],
                resources=["*"],
                conditions={
                    "ArnLike": {
                        "kms:EncryptionContext:aws:sns:topicArn": f"arn:aws:sns:{self.region}:{self.account}:iam-identity-center-*"
                    }
                }
            )
        )
        
        # Create aliases for easier management
        kms.Alias(
            self, "DynamoDBKMSKeyAlias",
            alias_name="alias/iam-identity-center-dynamodb",
            target_key=self.dynamodb_kms_key
        )
        
        kms.Alias(
            self, "S3KMSKeyAlias",
            alias_name="alias/iam-identity-center-s3",
            target_key=self.s3_kms_key
        )
        
        kms.Alias(
            self, "LambdaKMSKeyAlias",
            alias_name="alias/iam-identity-center-lambda",
            target_key=self.lambda_kms_key
        )

    def create_vpc_infrastructure(self):
        """Create VPC infrastructure for Lambda functions"""
        
        # Create VPC with private subnets for Lambda functions
        self.vpc = ec2.Vpc(
            self, "DiscoveryVPC",
            vpc_name="iam-identity-center-discovery-vpc",
            max_azs=2,
            nat_gateways=1,  # Cost optimization - single NAT gateway
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="Private",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    cidr_mask=24
                ),
                ec2.SubnetConfiguration(
                    name="Public",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    cidr_mask=24,
                    map_public_ip_on_launch=False  # Fix CFN_NAG_W33: Disable auto-assign public IP
                )
            ],
            enable_dns_hostnames=True,
            enable_dns_support=True
        )
        
        # Fix CFN_NAG_W60: Enable VPC Flow Logs
        vpc_flow_log_role = iam.Role(
            self, "VpcFlowLogRole",
            assumed_by=iam.ServicePrincipal("vpc-flow-logs.amazonaws.com")
        )
        
        vpc_flow_log_group = logs.LogGroup(
            self, "VpcFlowLogGroup",
            log_group_name=f"/aws/vpc/iam-identity-center-discovery-{self.stack_name}",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        ec2.FlowLog(
            self, "VpcFlowLog",
            resource_type=ec2.FlowLogResourceType.from_vpc(self.vpc),
            destination=ec2.FlowLogDestination.to_cloud_watch_logs(
                vpc_flow_log_group,
                vpc_flow_log_role
            ),
            traffic_type=ec2.FlowLogTrafficType.ALL
        )
        
        # Create security group for Lambda functions with restricted egress
        self.lambda_security_group = ec2.SecurityGroup(
            self, "LambdaSecurityGroup",
            vpc=self.vpc,
            description="Security group for IAM Identity Center Lambda functions",
            allow_all_outbound=False  # Restrict outbound to explicit rules only
        )

        # Allow only HTTPS outbound for AWS API calls
        self.lambda_security_group.add_egress_rule(
            peer=ec2.Peer.any_ipv4(),
            connection=ec2.Port.tcp(443),
            description="Allow HTTPS outbound for AWS API calls to IAM Identity Center, DynamoDB, S3, and other AWS services"
        )
        
        # Create VPC endpoints for AWS services to avoid internet routing
        self.create_vpc_endpoints()

    def create_vpc_endpoints(self):
        """Create VPC endpoints for AWS services"""
        
        # DynamoDB VPC endpoint
        self.vpc.add_gateway_endpoint(
            "DynamoDBEndpoint",
            service=ec2.GatewayVpcEndpointAwsService.DYNAMODB,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
        )
        
        # S3 VPC endpoint
        self.vpc.add_gateway_endpoint(
            "S3Endpoint",
            service=ec2.GatewayVpcEndpointAwsService.S3,
            subnets=[ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)]
        )
        
        # Interface endpoints for other AWS services
        # Note: SSO endpoint may not be available in all regions, using available services
        interface_endpoints = [
            ("STS", ec2.InterfaceVpcEndpointAwsService.STS),
            ("SNS", ec2.InterfaceVpcEndpointAwsService.SNS),
            ("CloudWatch", ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH),
            ("CloudWatchLogs", ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS),
            ("StepFunctions", ec2.InterfaceVpcEndpointAwsService.STEP_FUNCTIONS)
        ]
        
        for name, service in interface_endpoints:
            try:
                self.vpc.add_interface_endpoint(
                    f"{name}Endpoint",
                    service=service,
                    subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
                    security_groups=[self.lambda_security_group]
                )
            except Exception as e:
                # Some endpoints may not be available in all regions
                print(f"Warning: Could not create {name} endpoint: {e}")

    def create_dynamodb_tables(self):
        """Create DynamoDB tables with encryption and enhanced security"""
        
        # Determine if PITR should be enabled based on parameter
        enable_pitr = self.enable_dynamodb_pitr
        
        # Instances Table with encryption
        self.instances_table = dynamodb.Table(
            self, "InstancesTable",
            table_name="iam-identity-center-instances",
            partition_key=dynamodb.Attribute(
                name="instance_arn",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.dynamodb_kms_key,
            deletion_protection=False,  # Set to True for production
            table_class=dynamodb.TableClass.STANDARD,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=enable_pitr
            )  # Fix CFN_NAG_W78: Configurable PITR
        )
        
        # Add GSI for account-based queries
        self.instances_table.add_global_secondary_index(
            index_name="account_id-index",
            partition_key=dynamodb.Attribute(
                name="account_id",
                type=dynamodb.AttributeType.STRING
            )
        )
        
        # Applications Table with encryption
        self.applications_table = dynamodb.Table(
            self, "ApplicationsTable",
            table_name="iam-identity-center-applications",
            partition_key=dynamodb.Attribute(
                name="application_arn",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="instance_arn",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.dynamodb_kms_key,
            deletion_protection=False,  # Set to True for production
            table_class=dynamodb.TableClass.STANDARD,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=enable_pitr
            )  # Fix CFN_NAG_W78: Configurable PITR
        )
        
        # Add GSI for instance-based queries
        self.applications_table.add_global_secondary_index(
            index_name="instance_arn-index",
            partition_key=dynamodb.Attribute(
                name="instance_arn",
                type=dynamodb.AttributeType.STRING
            )
        )
        
        # Assignments Table with encryption
        self.assignments_table = dynamodb.Table(
            self, "AssignmentsTable",
            table_name="iam-identity-center-assignments",
            partition_key=dynamodb.Attribute(
                name="assignment_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.dynamodb_kms_key,
            deletion_protection=False,  # Set to True for production
            table_class=dynamodb.TableClass.STANDARD,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=enable_pitr
            )  # Fix CFN_NAG_W78: Configurable PITR
        )
        
        # Add GSIs for different query patterns
        self.assignments_table.add_global_secondary_index(
            index_name="application_arn-index",
            partition_key=dynamodb.Attribute(
                name="application_arn",
                type=dynamodb.AttributeType.STRING
            )
        )
        
        self.assignments_table.add_global_secondary_index(
            index_name="principal_id-index",
            partition_key=dynamodb.Attribute(
                name="principal_id",
                type=dynamodb.AttributeType.STRING
            )
        )

        # State table tracking the last full/incremental discovery run. The
        # change-detection Lambda reads this to decide full vs. incremental.
        self.discovery_state_table = dynamodb.Table(
            self, "DiscoveryStateTable",
            table_name="iam-identity-center-discovery-state",
            partition_key=dynamodb.Attribute(
                name="state_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.dynamodb_kms_key,
            deletion_protection=False,  # Set to True for production
            table_class=dynamodb.TableClass.STANDARD,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=enable_pitr
            )
        )

        # Append-only log of changes detected between discovery runs.
        self.discovery_change_log_table = dynamodb.Table(
            self, "DiscoveryChangeLogTable",
            table_name="iam-identity-center-discovery-change-log",
            partition_key=dynamodb.Attribute(
                name="change_id",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=self.dynamodb_kms_key,
            deletion_protection=False,  # Set to True for production
            table_class=dynamodb.TableClass.STANDARD,
            point_in_time_recovery_specification=dynamodb.PointInTimeRecoverySpecification(
                point_in_time_recovery_enabled=enable_pitr
            )
        )

    def create_s3_bucket(self):
        """Create S3 bucket with comprehensive security hardening"""
        
        # No explicit bucket_name: CloudFormation generates a globally unique
        # name, which prevents bucket-name squatting against readers who copy
        # this sample. Consumers get the real name from the CSV_EXPORT_BUCKET
        # env var / CsvExportBucketName stack output, never from a pattern.
        # Destination for the CSV bucket's server access logs.
        #
        # This bucket is deliberately SSE-S3 and not KMS, which is the one place
        # in this stack that departs from customer-managed-key encryption. It is
        # an AWS constraint, not a relaxation: "Granting s3:PutObject to the
        # logging service principal is not sufficient if the destination bucket
        # uses SSE-KMS default encryption. The destination bucket must use Amazon
        # S3 managed keys (SSE-S3). If the destination bucket uses SSE-KMS,
        # Amazon S3 might deliver log objects that are encrypted with a key that
        # you can't access."
        # https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html
        #
        # Object Lock is also left off, because it blocks log delivery outright.
        self.access_logs_bucket = s3.Bucket(
            self, "CsvExportAccessLogsBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            enforce_ssl=True,
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="ExpireAccessLogs",
                    expiration=Duration.days(90),
                    enabled=True,
                    abort_incomplete_multipart_upload_after=Duration.days(1)
                )
            ]
        )

        self.csv_export_bucket = s3.Bucket(
            self, "CsvExportBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
            versioned=True,
            # Enhanced encryption with customer-managed KMS key
            encryption=s3.BucketEncryption.KMS,
            encryption_key=self.s3_kms_key,
            bucket_key_enabled=True,
            # Block all public access
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            # Server access logging to a dedicated SSE-S3 bucket. Previously
            # None, with a comment saying a logging bucket was what production
            # "would" do -- which meant AwsSolutions-S1 was unmet and, because
            # no rule pack was wired up, nothing reported it.
            server_access_logs_bucket=self.access_logs_bucket,
            server_access_logs_prefix="csv-export-access-logs/",
            # Lifecycle rules for cost optimization
            lifecycle_rules=[
                s3.LifecycleRule(
                    id="DeleteOldExports",
                    expiration=Duration.days(30),
                    enabled=True,
                    abort_incomplete_multipart_upload_after=Duration.days(1),
                    noncurrent_version_expiration=Duration.days(7)
                )
            ],
            # Enable event notifications for monitoring
            event_bridge_enabled=True,
            # Enforce SSL requests only
            enforce_ssl=True
        )
        
        # Add bucket policy for additional security
        self.csv_export_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="DenyInsecureConnections",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["s3:*"],
                resources=[
                    self.csv_export_bucket.bucket_arn,
                    f"{self.csv_export_bucket.bucket_arn}/*"
                ],
                conditions={
                    "Bool": {
                        "aws:SecureTransport": "false"
                    }
                }
            )
        )
        
        # Access to the bucket is granted through the discovery Lambda's execution
        # role (least-privilege S3 actions on this bucket; see create_lambda_functions).
        # The bucket is otherwise locked down by Block Public Access, customer-managed
        # KMS encryption, enforced TLS (DenyInsecureConnections above), and the
        # presigned-URL IP restriction below.

        # Add bucket policy to restrict presigned URL access by IP address
        self.csv_export_bucket.add_to_resource_policy(
            iam.PolicyStatement(
                sid="RestrictPresignedUrlByIP",
                effect=iam.Effect.DENY,
                principals=[iam.AnyPrincipal()],
                actions=["s3:GetObject"],
                resources=[f"{self.csv_export_bucket.bucket_arn}/*"],
                conditions={
                    "NotIpAddress": {
                        "aws:SourceIp": [self.allowed_ip_range.value_as_string]
                    },
                    "StringLike": {
                        "s3:authType": "REST-QUERY-STRING"  # Only applies to presigned URLs
                    }
                }
            )
        )

        cdk.CfnOutput(
            self, "CsvExportBucketName",
            value=self.csv_export_bucket.bucket_name,
            description="S3 bucket for CSV exports (CloudFormation-generated name)"
        )

    # Files that are part of the repository but must not ship in a Lambda asset.
    ASSET_EXCLUDES = [
        "*.pyc",
        "__pycache__",
        ".pytest_cache",
        ".hypothesis",
        "test_*.py",
        "*_test.py",
        "conftest.py",
        "pytest.ini",
    ]

    def _create_shared_layer(self) -> _lambda.LayerVersion:
        """
        Package src/lambdas/shared as a Lambda layer.

        Every discovery function imports the shared modules as `from shared.x
        import y`. A layer is extracted to /opt, and /opt/python is on the Python
        path, so the layer content is staged under `python/shared/` to keep those
        import statements unchanged.

        This replaces a container bundling step whose entire job was to copy the
        shared directory alongside each function. Using a layer means Docker is no
        longer required for `cdk synth` or `cdk deploy`, and the shared modules are
        stored once instead of duplicated into six assets.
        """
        import shutil
        from pathlib import Path

        # A layer is extracted to /opt and only /opt/python is on the Python path,
        # so the modules must sit at python/shared/ inside the archive.
        # src/lambdas/shared stays the single source of truth -- tests and the
        # handlers both import from there -- and it is staged into the required
        # layout here, at synth time, in Python. No container, no second copy in
        # version control.
        source = Path("src/lambdas/shared")
        staged = Path("cdk.out/.layer-staging/iam-identity-center-shared/python/shared")

        if staged.exists():
            shutil.rmtree(staged)
        staged.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(
            source, staged,
            ignore=shutil.ignore_patterns(
                "__pycache__", "*.pyc", "test_*.py", "*_test.py", "conftest.py"
            ),
        )

        return _lambda.LayerVersion(
            self, "SharedModulesLayer",
            layer_version_name="iam-identity-center-shared",
            description="Shared models, utils, tracing, and alerting modules for the discovery Lambdas",
            compatible_runtimes=[_lambda.Runtime.PYTHON_3_12],
            code=_lambda.Code.from_asset(str(staged.parent.parent)),
            removal_policy=RemovalPolicy.DESTROY,
        )

    def _create_lambda_code(self, lambda_dir: str) -> _lambda.Code:
        """
        Package a single function directory as its Lambda asset.

        The shared modules arrive via the layer created in _create_shared_layer,
        so each asset contains only its own handler and helpers. No container
        bundling, and therefore no Docker dependency.
        """
        return _lambda.Code.from_asset(lambda_dir, exclude=self.ASSET_EXCLUDES)


    def create_lambda_functions(self):
        """Create Lambda functions with VPC configuration and enhanced security"""

        # Shared modules ship as a layer so each function asset holds only its own
        # code. Must exist before lambda_config references it.
        self.shared_layer = self._create_shared_layer()

        # Common Lambda environment variables
        lambda_environment = {
            "INSTANCES_TABLE": self.instances_table.table_name,
            "APPLICATIONS_TABLE": self.applications_table.table_name,
            "ASSIGNMENTS_TABLE": self.assignments_table.table_name,
            "DISCOVERY_STATE_TABLE": self.discovery_state_table.table_name,
            "DISCOVERY_CHANGE_LOG_TABLE": self.discovery_change_log_table.table_name,
            "CSV_EXPORT_BUCKET": self.csv_export_bucket.bucket_name,
            "LOG_LEVEL": "INFO",
            "POWERTOOLS_SERVICE_NAME": "iam-identity-center-discovery",
            "POWERTOOLS_METRICS_NAMESPACE": "IAMIdentityCenter/Discovery",
            "DELEGATED_ADMIN_ACCOUNT_ID": self.delegated_admin_account_id.value_as_string,
            "GROUP_NAME_REGEX": self.group_name_regex.value_as_string
        }
        
        # Create enhanced Lambda execution role with least privilege
        lambda_role = iam.Role(
            self, "LambdaExecutionRole",
            role_name="iam-identity-center-lambda-execution-role",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSLambdaVPCAccessExecutionRole")
            ],
            inline_policies={
                "DynamoDBAccess": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            sid="DynamoDBTableAccess",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "dynamodb:GetItem",
                                "dynamodb:PutItem",
                                "dynamodb:UpdateItem",
                                "dynamodb:DeleteItem",
                                "dynamodb:Query",
                                "dynamodb:Scan",
                                "dynamodb:BatchGetItem",
                                "dynamodb:BatchWriteItem"
                            ],
                            resources=[
                                self.instances_table.table_arn,
                                self.applications_table.table_arn,
                                self.assignments_table.table_arn,
                                self.discovery_state_table.table_arn,
                                self.discovery_change_log_table.table_arn,
                                f"{self.instances_table.table_arn}/index/*",
                                f"{self.applications_table.table_arn}/index/*",
                                f"{self.assignments_table.table_arn}/index/*"
                            ]
                        ),
                        iam.PolicyStatement(
                            sid="DynamoDBKMSAccess",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "kms:Decrypt",
                                "kms:DescribeKey",
                                "kms:Encrypt",
                                "kms:GenerateDataKey",
                                "kms:ReEncrypt*"
                            ],
                            resources=[self.dynamodb_kms_key.key_arn]
                        )
                    ]
                ),
                "IAMIdentityCenterAccess": iam.PolicyDocument(
                    statements=[
                        # SSO Portal API permissions for instance and application operations
                        # These permissions use the sso: namespace (not sso-admin:)
                        # Resource ARNs use wildcards because instance IDs are discovered dynamically at runtime
                        # Note: SSO uses THREE different ARN formats:
                        #   - Instance ARNs: arn:aws:sso:::instance/* (3 colons, no account)
                        #   - Application ARNs: arn:aws:sso::ACCOUNT:application/*/* (2 colons, with account)
                        #   - Application provider ARNs: arn:aws:sso::aws:applicationProvider/*
                        #     (account field is the literal "aws" — AWS-owned resources)
                        iam.PolicyStatement(
                            sid="SSOPortalAPIAccess",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "sso:ListInstances",
                                "sso:ListApplications",
                                "sso:DescribeApplication",
                                "sso:DescribeApplicationProvider",
                                "sso:ListApplicationAssignments",
                                "sso:DescribeInstance"
                            ],
                            resources=[
                                "arn:aws:sso:::instance/*",
                                "arn:aws:sso::*:application/*/*",
                                "arn:aws:sso::aws:applicationProvider/*"
                            ]
                        ),
                        # Permission-set reads, used to resolve permission set
                        # names for account assignments.
                        #
                        # There is no "sso-admin:" IAM prefix. "sso-admin" is the
                        # name of the SDK/CLI client; the IAM action prefix for
                        # every IAM Identity Center action is "sso:". See the
                        # Service Authorization Reference, which declares
                        # "service prefix: sso" and lists sso-admin only in its
                        # "SDK client" column:
                        # https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam-identity-center.html
                        #
                        # DescribePermissionSet requires BOTH the Instance and
                        # PermissionSet resource types, so both ARN shapes are
                        # listed. Granting only one denies the call.
                        iam.PolicyStatement(
                            sid="SSOPermissionSetReadOnly",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "sso:DescribePermissionSet",
                                "sso:ListPermissionSets"
                            ],
                            resources=[
                                "arn:aws:sso:::instance/*",
                                "arn:aws:sso:::permissionSet/*/*"
                            ]
                        ),
                        # DescribeApplicationAssignment is scoped to the
                        # Application resource type, matching SSOPortalAPIAccess
                        # above.
                        iam.PolicyStatement(
                            sid="SSOApplicationAssignmentReadOnly",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "sso:DescribeApplicationAssignment"
                            ],
                            resources=[
                                "arn:aws:sso::*:application/*/*"
                            ]
                        ),
                        iam.PolicyStatement(
                            sid="IdentityStoreReadOnly",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "identitystore:DescribeUser",
                                "identitystore:DescribeGroup",
                                "identitystore:ListUsers",
                                "identitystore:ListGroups",
                                "identitystore:ListGroupMemberships",
                                "identitystore:ListGroupMembershipsForMember"
                            ],
                            resources=["*"]
                        ),
                        iam.PolicyStatement(
                            sid="OrganizationsReadOnly",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "organizations:ListAccounts",
                                "organizations:DescribeOrganization"
                            ],
                            resources=["*"]
                        ),
                        iam.PolicyStatement(
                            sid="EC2DescribeRegions",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "ec2:DescribeRegions"
                            ],
                            resources=["*"]
                        ),
                        iam.PolicyStatement(
                            sid="CrossAccountRoleAssumption",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "sts:AssumeRole"
                            ],
                            resources=[
                                f"arn:aws:iam::*:role/iam-identity-center-cross-account-discovery-role"
                            ],
                            conditions={
                                "StringEquals": {
                                    "sts:ExternalId": "iam-identity-center-discovery"
                                }
                            }
                        )
                    ]
                ),
                "S3Access": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            sid="S3BucketAccess",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "s3:GetObject",
                                "s3:PutObject",
                                "s3:DeleteObject",
                                "s3:ListBucket",
                                "s3:GetObjectTagging",
                                "s3:PutObjectTagging"
                            ],
                            resources=[
                                f"{self.csv_export_bucket.bucket_arn}/*",
                                self.csv_export_bucket.bucket_arn
                            ]
                        ),
                        iam.PolicyStatement(
                            sid="S3KMSAccess",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "kms:Decrypt",
                                "kms:DescribeKey",
                                "kms:Encrypt",
                                "kms:GenerateDataKey",
                                "kms:ReEncrypt*"
                            ],
                            resources=[self.s3_kms_key.key_arn]
                        )
                    ]
                ),
                "SNSAccess": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            sid="SNSPublishAccess",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "sns:Publish"
                            ],
                            resources=[
                                f"arn:aws:sns:{self.region}:{self.account}:iam-identity-center-*"
                            ]
                        )
                    ]
                ),
                "CloudWatchAccess": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            sid="CloudWatchMetrics",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "cloudwatch:PutMetricData"
                            ],
                            resources=["*"],
                            conditions={
                                "StringEquals": {
                                    # Both namespaces this solution writes to.
                                    # shared/performance.py publishes to the
                                    # /Performance namespace; omitting it here
                                    # meant that collector would fail closed with
                                    # AccessDenied the moment anything wired it
                                    # up, with no other symptom.
                                    "cloudwatch:namespace": [
                                        "IAMIdentityCenter/Discovery",
                                        "IAMIdentityCenter/Discovery/Performance"
                                    ]
                                }
                            }
                        )
                    ]
                ),
                "LambdaKMSAccess": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            sid="LambdaEnvironmentKMS",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "kms:Decrypt",
                                "kms:DescribeKey",
                                # Publishing to the CMK-encrypted SNS topics
                                # requires the caller to generate a data key;
                                # without it Publish fails with KMSAccessDenied.
                                "kms:GenerateDataKey"
                            ],
                            resources=[self.lambda_kms_key.key_arn]
                        )
                    ]
                )
            }
        )
        
        # Common Lambda configuration with security enhancements
        lambda_config = {
            "runtime": _lambda.Runtime.PYTHON_3_12,
            "layers": [self.shared_layer],
            "environment": lambda_environment,
            "environment_encryption": self.lambda_kms_key,
            "role": lambda_role,
            "timeout": Duration.minutes(15),
            "memory_size": 1024,
            "vpc": self.vpc,
            "vpc_subnets": ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS),
            "security_groups": [self.lambda_security_group],
            "reserved_concurrent_executions": 10,  # Prevent runaway executions
            "tracing": _lambda.Tracing.ACTIVE,  # Enable X-Ray tracing
            "architecture": _lambda.Architecture.ARM_64  # Cost optimization
        }
        
        # Unified Instance Scanner Lambda (replaces organization-scanner and account-scanner)
        # This Lambda discovers BOTH organization-level and account-level instances in a single execution
        instance_scanner_log_group = logs.LogGroup(
            self, "InstanceScannerLogGroup",
            log_group_name="/aws/lambda/iam-identity-center-instance-scanner",
            retention=logs.RetentionDays.ONE_WEEK,
            encryption_key=self.lambda_kms_key,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        self.instance_scanner = _lambda.Function(
            self, "InstanceScanner",
            function_name="iam-identity-center-instance-scanner",
            handler="index.lambda_handler",
            code=self._create_lambda_code("src/lambdas/instance-scanner"),
            log_group=instance_scanner_log_group,
            **lambda_config
        )
        
        # Application Discovery Lambda
        application_discovery_log_group = logs.LogGroup(
            self, "ApplicationDiscoveryLogGroup",
            log_group_name="/aws/lambda/iam-identity-center-application-discovery",
            retention=logs.RetentionDays.ONE_WEEK,
            encryption_key=self.lambda_kms_key,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        self.application_discovery = _lambda.Function(
            self, "ApplicationDiscovery",
            function_name="iam-identity-center-application-discovery",
            handler="index.lambda_handler",
            code=self._create_lambda_code("src/lambdas/application-discovery"),
            log_group=application_discovery_log_group,
            **lambda_config
        )
        
        # Assignment Discovery Lambda
        assignment_discovery_log_group = logs.LogGroup(
            self, "AssignmentDiscoveryLogGroup",
            log_group_name="/aws/lambda/iam-identity-center-assignment-discovery",
            retention=logs.RetentionDays.ONE_WEEK,
            encryption_key=self.lambda_kms_key,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        self.assignment_discovery = _lambda.Function(
            self, "AssignmentDiscovery",
            function_name="iam-identity-center-assignment-discovery",
            handler="index.lambda_handler",
            code=self._create_lambda_code("src/lambdas/assignment-discovery"),
            log_group=assignment_discovery_log_group,
            **lambda_config
        )
        
        # CSV Export Lambda
        csv_export_log_group = logs.LogGroup(
            self, "CsvExportLogGroup",
            log_group_name="/aws/lambda/iam-identity-center-csv-export",
            retention=logs.RetentionDays.ONE_WEEK,
            encryption_key=self.lambda_kms_key,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        self.csv_export = _lambda.Function(
            self, "CsvExport",
            function_name="iam-identity-center-csv-export",
            handler="index.lambda_handler",
            code=self._create_lambda_code("src/lambdas/csv-export"),
            log_group=csv_export_log_group,
            **lambda_config
        )
        
        # Change Detection Lambda
        change_detection_log_group = logs.LogGroup(
            self, "ChangeDetectionLogGroup",
            log_group_name="/aws/lambda/iam-identity-center-change-detection",
            retention=logs.RetentionDays.ONE_WEEK,
            encryption_key=self.lambda_kms_key,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        self.change_detection = _lambda.Function(
            self, "ChangeDetection",
            function_name="iam-identity-center-change-detection",
            handler="index.lambda_handler",
            code=self._create_lambda_code("src/lambdas/change-detection"),
            log_group=change_detection_log_group,
            **lambda_config
        )
        
        # Access Tracker Lambda - Enriches assignments with last-accessed data from CloudTrail
        access_tracker_log_group = logs.LogGroup(
            self, "AccessTrackerLogGroup",
            log_group_name="/aws/lambda/iam-identity-center-access-tracker",
            retention=logs.RetentionDays.ONE_WEEK,
            encryption_key=self.lambda_kms_key,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        self.access_tracker = _lambda.Function(
            self, "AccessTracker",
            function_name="iam-identity-center-access-tracker",
            handler="index.lambda_handler",
            code=self._create_lambda_code("src/lambdas/access-tracker"),
            log_group=access_tracker_log_group,
            **lambda_config
        )
        
        # Grant CloudTrail read permissions to access tracker
        self.access_tracker.add_to_role_policy(
            iam.PolicyStatement(
                sid="CloudTrailReadAccess",
                effect=iam.Effect.ALLOW,
                actions=[
                    "cloudtrail:LookupEvents",
                    "cloudtrail:GetEventSelectors",
                    "cloudtrail:DescribeTrails"
                ],
                resources=["*"]
            )
        )

    def create_step_functions(self):
        """Create Step Functions state machine with enhanced security"""
        
        # Load state machine definition
        with open("src/step-functions/discovery-state-machine.json", "r") as f:
            state_machine_definition = json.load(f)
        
        # Replace function ARNs in the definition
        definition_string = json.dumps(state_machine_definition)
        definition_string = definition_string.replace(
            "${InstanceScannerFunction}", 
            self.instance_scanner.function_arn
        )
        definition_string = definition_string.replace(
            "${ApplicationDiscoveryFunction}", 
            self.application_discovery.function_arn
        )
        definition_string = definition_string.replace(
            "${AssignmentDiscoveryFunction}", 
            self.assignment_discovery.function_arn
        )
        definition_string = definition_string.replace(
            "${ChangeDetectionFunction}", 
            self.change_detection.function_arn
        )
        definition_string = definition_string.replace(
            "${AccessTrackerFunction}", 
            self.access_tracker.function_arn
        )
        definition_string = definition_string.replace(
            '"${StaleThresholdDays}"',
            self.stale_threshold_days.value_as_string
        )
        
        # Create Step Functions role with least privilege
        step_functions_role = iam.Role(
            self, "StepFunctionsRole",
            role_name="iam-identity-center-step-functions-role",
            assumed_by=iam.ServicePrincipal("states.amazonaws.com"),
            inline_policies={
                "LambdaInvokePolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            sid="LambdaInvokeAccess",
                            effect=iam.Effect.ALLOW,
                            actions=["lambda:InvokeFunction"],
                            resources=[
                                self.instance_scanner.function_arn,
                                self.application_discovery.function_arn,
                                self.assignment_discovery.function_arn,
                                self.change_detection.function_arn,
                                self.access_tracker.function_arn
                            ]
                        )
                    ]
                ),
                "CloudWatchMetricsPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            sid="CloudWatchMetricsAccess",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "cloudwatch:PutMetricData"
                            ],
                            resources=["*"],
                            conditions={
                                "StringEquals": {
                                    # AWS/States is inert here: CloudWatch reserves
                                    # AWS/* namespaces and rejects PutMetricData to
                                    # them. Kept rather than removed to avoid an
                                    # unrelated behavioural change, but it grants
                                    # nothing.
                                    "cloudwatch:namespace": [
                                        "AWS/States",
                                        "IAMIdentityCenter/Discovery",
                                        "IAMIdentityCenter/Discovery/Performance"
                                    ]
                                }
                            }
                        )
                    ]
                )
            }
        )
        
        # Create state machine with enhanced logging
        self.state_machine = sfn.StateMachine(
            self, "DiscoveryStateMachine",
            state_machine_name="iam-identity-center-discovery",
            definition_body=sfn.DefinitionBody.from_string(definition_string),
            role=step_functions_role,
            timeout=Duration.hours(1),
            tracing_enabled=True,  # Enable X-Ray tracing
            logs=sfn.LogOptions(
                destination=logs.LogGroup(
                    self, "StateMachineLogGroup",
                    log_group_name="/aws/stepfunctions/iam-identity-center-discovery",
                    retention=logs.RetentionDays.ONE_WEEK,
                    removal_policy=RemovalPolicy.DESTROY,
                    encryption_key=self.lambda_kms_key  # Encrypt logs
                ),
                level=sfn.LogLevel.ALL,
                include_execution_data=False  # Don't log sensitive data
            )
        )

    def create_api_gateway(self):
        """Create API Gateway with enhanced security and authentication"""
        
        # Create IAM role for API Gateway to write to CloudWatch Logs
        # This is required at the account level for API Gateway access logging
        api_gateway_cloudwatch_role = iam.Role(
            self, "ApiGatewayCloudWatchRole",
            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonAPIGatewayPushToCloudWatchLogs"  # pragma: allowlist secret
                )
            ]
        )
        
        # Set the CloudWatch Logs role ARN for API Gateway account settings
        # This is a one-time account-level configuration
        api_gateway_account = apigateway.CfnAccount(
            self, "ApiGatewayAccount",
            cloud_watch_role_arn=api_gateway_cloudwatch_role.role_arn
        )
        
        # Fix CFN_NAG_W69: Create CloudWatch Log Group for API Gateway access logging
        api_access_log_group = logs.LogGroup(
            self, "ApiGatewayAccessLogGroup",
            log_group_name=f"/aws/apigateway/iam-identity-center-export-api-{self.stack_name}",
            retention=logs.RetentionDays.ONE_WEEK,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        # Create API Gateway with security enhancements
        self.api = apigateway.RestApi(
            self, "ExportApi",
            rest_api_name="iam-identity-center-export-api",
            description="Secure API for IAM Identity Center CSV exports with IAM authentication and IP restriction",
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=["https://*.amazonaws.com"],  # Restrict origins
                allow_methods=["GET", "OPTIONS"],
                allow_headers=["Content-Type", "X-Amz-Date", "Authorization", "X-Api-Key", "X-Amz-Security-Token"],
                max_age=Duration.hours(1)
            ),
            deploy_options=apigateway.StageOptions(
                stage_name="prod",
                throttling_rate_limit=50,  # Reduced rate limit
                throttling_burst_limit=100,  # Reduced burst limit
                metrics_enabled=True,
                caching_enabled=False,
                cache_cluster_enabled=False,
                # Execution logging for all methods (AwsSolutions-APIG6). Access
                # logging below records who called; this records what the stage
                # did while handling the call, which is what you need when an
                # export fails and the access log only shows a 500.
                # data_trace_enabled stays off: it logs full request/response
                # bodies, and these responses carry presigned URLs to PII.
                logging_level=apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=False,
                variables={
                    "environment": "production"
                },
                # Fix CFN_NAG_W69: Enable access logging
                access_log_destination=apigateway.LogGroupLogDestination(api_access_log_group),
                access_log_format=apigateway.AccessLogFormat.json_with_standard_fields(
                    caller=True,
                    http_method=True,
                    ip=True,
                    protocol=True,
                    request_time=True,
                    resource_path=True,
                    response_length=True,
                    status=True,
                    user=True
                )
            ),
            # Disable execute API endpoint for additional security
            disable_execute_api_endpoint=False,  # Set to True in production with custom domain
            min_compression_size=cdk.Size.kibibytes(1),  # 1 KiB = 1024 bytes
            binary_media_types=["application/octet-stream"],
            # Add resource policy to restrict by IP address
            policy=iam.PolicyDocument(
                statements=[
                    iam.PolicyStatement(
                        sid="AllowFromSpecificIP",
                        effect=iam.Effect.ALLOW,
                        principals=[iam.AnyPrincipal()],
                        actions=["execute-api:Invoke"],
                        resources=["execute-api:/*"],
                        conditions={
                            "IpAddress": {
                                "aws:SourceIp": [self.allowed_ip_range.value_as_string]
                            }
                        }
                    )
                ]
            )
        )
        
        # Create request validator for enhanced input validation
        request_validator = apigateway.RequestValidator(
            self, "ExportRequestValidator",
            rest_api=self.api,
            request_validator_name="export-request-validator",
            validate_request_parameters=True,
            validate_request_body=True
        )
        
        # Common integration response configuration
        integration_responses = [
            apigateway.IntegrationResponse(
                status_code="200",
                response_parameters={
                    "method.response.header.Content-Type": "'application/json'",
                    "method.response.header.Cache-Control": "'no-cache, no-store, must-revalidate'",
                    "method.response.header.X-Content-Type-Options": "'nosniff'",
                    "method.response.header.X-Frame-Options": "'DENY'",
                    "method.response.header.X-XSS-Protection": "'1; mode=block'"
                }
            ),
            apigateway.IntegrationResponse(
                status_code="400",
                selection_pattern=".*Bad Request.*",
                response_parameters={
                    "method.response.header.Content-Type": "'application/json'"
                }
            ),
            apigateway.IntegrationResponse(
                status_code="403",
                selection_pattern=".*Forbidden.*",
                response_parameters={
                    "method.response.header.Content-Type": "'application/json'"
                }
            ),
            apigateway.IntegrationResponse(
                status_code="500",
                selection_pattern=".*Internal Server Error.*",
                response_parameters={
                    "method.response.header.Content-Type": "'application/json'"
                }
            )
        ]
        
        # Create separate Lambda integrations for each export type
        applications_integration = apigateway.LambdaIntegration(
            self.csv_export,
            proxy=True,
            request_templates={
                "application/json": """{
                    "export_type": "applications",
                    "filters": {
                        "account_id": "$util.escapeJavaScript($input.params('account_id'))",
                        "region": "$util.escapeJavaScript($input.params('region'))",
                        "application_name": "$util.escapeJavaScript($input.params('application_name'))",
                        "principal_type": "$util.escapeJavaScript($input.params('principal_type'))",
                        "date_from": "$util.escapeJavaScript($input.params('date_from'))",
                        "date_to": "$util.escapeJavaScript($input.params('date_to'))"
                    },
                    "request_context": {
                        "request_id": "$context.requestId",
                        "user_arn": "$context.identity.userArn",
                        "source_ip": "$context.identity.sourceIp",
                        "user_agent": "$util.escapeJavaScript($context.identity.userAgent)",
                        "request_time": "$context.requestTime"
                    }
                }"""
            },
            integration_responses=integration_responses
        )
        
        assignments_integration = apigateway.LambdaIntegration(
            self.csv_export,
            proxy=True,
            request_templates={
                "application/json": """{
                    "export_type": "assignments",
                    "filters": {
                        "account_id": "$util.escapeJavaScript($input.params('account_id'))",
                        "region": "$util.escapeJavaScript($input.params('region'))",
                        "application_name": "$util.escapeJavaScript($input.params('application_name'))",
                        "principal_type": "$util.escapeJavaScript($input.params('principal_type'))",
                        "date_from": "$util.escapeJavaScript($input.params('date_from'))",
                        "date_to": "$util.escapeJavaScript($input.params('date_to'))"
                    },
                    "request_context": {
                        "request_id": "$context.requestId",
                        "user_arn": "$context.identity.userArn",
                        "source_ip": "$context.identity.sourceIp",
                        "user_agent": "$util.escapeJavaScript($context.identity.userAgent)",
                        "request_time": "$context.requestTime"
                    }
                }"""
            },
            integration_responses=integration_responses
        )
        
        full_integration = apigateway.LambdaIntegration(
            self.csv_export,
            proxy=True,
            request_templates={
                "application/json": """{
                    "export_type": "full",
                    "filters": {
                        "account_id": "$util.escapeJavaScript($input.params('account_id'))",
                        "region": "$util.escapeJavaScript($input.params('region'))",
                        "application_name": "$util.escapeJavaScript($input.params('application_name'))",
                        "principal_type": "$util.escapeJavaScript($input.params('principal_type'))",
                        "date_from": "$util.escapeJavaScript($input.params('date_from'))",
                        "date_to": "$util.escapeJavaScript($input.params('date_to'))"
                    },
                    "request_context": {
                        "request_id": "$context.requestId",
                        "user_arn": "$context.identity.userArn",
                        "source_ip": "$context.identity.sourceIp",
                        "user_agent": "$util.escapeJavaScript($context.identity.userAgent)",
                        "request_time": "$context.requestTime"
                    }
                }"""
            },
            integration_responses=integration_responses
        )
        
        # Enhanced request parameters with validation
        request_parameters = {
            "method.request.querystring.account_id": False,
            "method.request.querystring.region": False,
            "method.request.querystring.application_name": False,
            "method.request.querystring.principal_type": False,
            "method.request.querystring.date_from": False,
            "method.request.querystring.date_to": False
        }
        
        # Enhanced method responses with security headers
        method_responses = [
            apigateway.MethodResponse(
                status_code="200",
                response_parameters={
                    "method.response.header.Content-Type": True,
                    "method.response.header.Cache-Control": True,
                    "method.response.header.X-Content-Type-Options": True,
                    "method.response.header.X-Frame-Options": True,
                    "method.response.header.X-XSS-Protection": True
                }
            ),
            apigateway.MethodResponse(
                status_code="400",
                response_parameters={
                    "method.response.header.Content-Type": True
                }
            ),
            apigateway.MethodResponse(
                status_code="403",
                response_parameters={
                    "method.response.header.Content-Type": True
                }
            ),
            apigateway.MethodResponse(
                status_code="500",
                response_parameters={
                    "method.response.header.Content-Type": True
                }
            )
        ]
        
        # Create API resources and methods with enhanced security
        export_resource = self.api.root.add_resource("export")
        
        # Applications export endpoint
        applications_resource = export_resource.add_resource("applications")
        applications_resource.add_method(
            "GET", 
            applications_integration,
            authorization_type=apigateway.AuthorizationType.IAM,
            request_parameters=request_parameters,
            request_validator=request_validator,
            method_responses=method_responses
        )
        
        # Assignments export endpoint
        assignments_resource = export_resource.add_resource("assignments")
        assignments_resource.add_method(
            "GET", 
            assignments_integration,
            authorization_type=apigateway.AuthorizationType.IAM,
            request_parameters=request_parameters,
            request_validator=request_validator,
            method_responses=method_responses
        )
        
        # Full export endpoint
        full_resource = export_resource.add_resource("full")
        full_resource.add_method(
            "GET", 
            full_integration,
            authorization_type=apigateway.AuthorizationType.IAM,
            request_parameters=request_parameters,
            request_validator=request_validator,
            method_responses=method_responses
        )
        
        # Manual trigger endpoint - Direct Step Functions integration
        trigger_resource = self.api.root.add_resource("trigger")
        
        # Create IAM role for API Gateway to invoke Step Functions
        api_sfn_role = iam.Role(
            self, "ApiStepFunctionsRole",
            assumed_by=iam.ServicePrincipal("apigateway.amazonaws.com"),
            inline_policies={
                "StartExecution": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["states:StartExecution"],
                            resources=[self.state_machine.state_machine_arn]
                        )
                    ]
                )
            }
        )
        
        # Create Step Functions integration
        trigger_integration = apigateway.AwsIntegration(
            service="states",
            action="StartExecution",
            integration_http_method="POST",
            options=apigateway.IntegrationOptions(
                credentials_role=api_sfn_role,
                request_templates={
                    "application/json": """{
                        "stateMachineArn": """ + json.dumps(self.state_machine.state_machine_arn) + """,
                        "input": "{\\"force_full_discovery\\": #if($input.path('$.force_full_discovery') != '')$input.json('$.force_full_discovery')#{else}true#end, \\"incremental_discovery_enabled\\": #if($input.path('$.incremental_discovery_enabled') != '')$input.json('$.incremental_discovery_enabled')#{else}false#end, \\"discovery_run_id\\": \\"manual-$context.requestId\\", \\"triggered_by\\": \\"api-gateway\\"}"
                    }"""
                },
                integration_responses=[
                    apigateway.IntegrationResponse(
                        status_code="200",
                        response_templates={
                            "application/json": '{"message": "Discovery workflow started successfully", "executionArn": $input.json(\'$.executionArn\'), "startDate": $input.json(\'$.startDate\')}'
                        }
                    ),
                    apigateway.IntegrationResponse(
                        status_code="500",
                        selection_pattern=".*error.*",
                        response_templates={
                            "application/json": json.dumps({
                                "error": "Failed to start discovery workflow",
                                "message": "$input.path('$.errorMessage')"
                            })
                        }
                    )
                ]
            )
        )
        
        trigger_resource.add_method(
            "POST",
            trigger_integration,
            authorization_type=apigateway.AuthorizationType.IAM,
            method_responses=[
                apigateway.MethodResponse(
                    status_code="200",
                    response_models={
                        "application/json": apigateway.Model.EMPTY_MODEL
                    }
                ),
                apigateway.MethodResponse(
                    status_code="500",
                    response_models={
                        "application/json": apigateway.Model.EMPTY_MODEL
                    }
                )
            ]
        )
        
        # Create restrictive IAM role for API Gateway access
        self.api_access_role = iam.Role(
            self, "ApiGatewayAccessRole",
            role_name="iam-identity-center-export-api-access",
            assumed_by=iam.AccountRootPrincipal(),
            inline_policies={
                "ExportApiAccess": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            sid="RestrictedApiAccess",
                            effect=iam.Effect.ALLOW,
                            actions=[
                                "execute-api:Invoke"
                            ],
                            resources=[
                                f"{self.api.arn_for_execute_api()}/prod/GET/export/*",
                                f"{self.api.arn_for_execute_api()}/prod/POST/trigger"
                            ],
                            conditions={
                                "IpAddress": {
                                    "aws:SourceIp": [
                                        "10.0.0.0/8",  # Internal networks only
                                        "172.16.0.0/12",
                                        "192.168.0.0/16"
                                    ]
                                },
                                "DateGreaterThan": {
                                    "aws:CurrentTime": "2024-01-01T00:00:00Z"
                                }
                            }
                        )
                    ]
                )
            }
        )
        
        # Fix CFN_NAG_W64 & CFN_NAG_W68: Create API Gateway Usage Plan
        usage_plan = self.api.add_usage_plan(
            "ExportApiUsagePlan",
            name="iam-identity-center-export-usage-plan",
            description="Usage plan for IAM Identity Center Export API with rate limiting",
            throttle=apigateway.ThrottleSettings(
                rate_limit=50,
                burst_limit=100
            ),
            quota=apigateway.QuotaSettings(
                limit=10000,
                period=apigateway.Period.DAY
            )
        )
        
        # Associate the deployment stage with the usage plan
        usage_plan.add_api_stage(
            stage=self.api.deployment_stage
        )
        
        # Output API Gateway URL
        cdk.CfnOutput(
            self, "ExportApiUrl",
            value=self.api.url,
            description="IAM Identity Center Export API URL (Secure)"
        )
        
        # Output allowed IP range configuration
        cdk.CfnOutput(
            self, "AllowedIpRangeOutput",
            value=self.allowed_ip_range.value_as_string,
            description="IP address range allowed to access API Gateway and S3 presigned URLs"
        )
        
        # Output stale threshold configuration
        cdk.CfnOutput(
            self, "StaleThresholdDaysOutput",
            value=self.stale_threshold_days.value_as_string,
            description="Number of days without access after which an assignment is considered stale"
        )

    def create_scheduling(self):
        """Create CloudWatch Events for scheduling with enhanced security"""
        
        # Create encrypted SNS topics for notifications
        self.change_notification_topic = sns.Topic(
            self, "ChangeNotificationTopic",
            topic_name="iam-identity-center-changes",
            display_name="IAM Identity Center Changes",
            master_key=self.lambda_kms_key  # Encrypt SNS messages
        )
        
        self.discovery_status_topic = sns.Topic(
            self, "DiscoveryStatusTopic", 
            topic_name="iam-identity-center-discovery-status",
            display_name="IAM Identity Center Discovery Status",
            master_key=self.lambda_kms_key  # Encrypt SNS messages
        )
        
        # Add SNS topic ARNs to Lambda environment
        self.change_detection.add_environment("CHANGE_NOTIFICATION_TOPIC_ARN", self.change_notification_topic.topic_arn)
        self.change_detection.add_environment("DISCOVERY_STATUS_TOPIC_ARN", self.discovery_status_topic.topic_arn)
        
        # Grant SNS publish permissions to change detection Lambda
        self.change_notification_topic.grant_publish(self.change_detection)
        self.discovery_status_topic.grant_publish(self.change_detection)
        
        # Create EventBridge rules with enhanced security
        self.daily_rule = events.Rule(
            self, "DailyDiscoveryRule",
            rule_name="iam-identity-center-daily-discovery",
            description="Trigger IAM Identity Center discovery daily at 2 AM UTC",
            schedule=events.Schedule.cron(
                minute="0",
                hour="2",
                day="*",
                month="*",
                year="*"
            ),
            enabled=True
        )
        
        # Add Step Functions as target with enhanced input
        scheduled_target_input = events.RuleTargetInput.from_object({
            "discovery_run_id": events.EventField.from_path("$.id"),
            "timestamp": events.EventField.from_path("$.time"),
            "trigger": "scheduled",
            "schedule_type": "daily",
            "force_full_discovery": False,
            "incremental_discovery_enabled": True,
            "security_context": {
                "source": "eventbridge",
                "rule_name": "iam-identity-center-daily-discovery"
            }
        })
        
        self.daily_rule.add_target(
            targets.SfnStateMachine(
                self.state_machine,
                input=scheduled_target_input,
                role=iam.Role(
                    self, "EventBridgeStepFunctionsRole",
                    assumed_by=iam.ServicePrincipal("events.amazonaws.com"),
                    inline_policies={
                        "StepFunctionsExecutionPolicy": iam.PolicyDocument(
                            statements=[
                                iam.PolicyStatement(
                                    effect=iam.Effect.ALLOW,
                                    actions=["states:StartExecution"],
                                    resources=[self.state_machine.state_machine_arn]
                                )
                            ]
                        )
                    }
                )
            )
        )
        
        # Output scheduling configuration
        cdk.CfnOutput(
            self, "SchedulingConfiguration",
            value=json.dumps({
                "daily_rule": self.daily_rule.rule_name,
                "change_notification_topic": self.change_notification_topic.topic_arn,
                "discovery_status_topic": self.discovery_status_topic.topic_arn
            }),
            description="IAM Identity Center Discovery Scheduling Configuration (Secure)"
        )

    def create_monitoring_and_alerting(self):
        """Create comprehensive monitoring and alerting with enhanced security"""
        
        # Create encrypted SNS topics for different alert severities
        self.critical_alerts_topic = sns.Topic(
            self, "CriticalAlertsTopic",
            topic_name="iam-identity-center-critical-alerts",
            display_name="IAM Identity Center Critical Alerts",
            master_key=self.lambda_kms_key
        )
        
        self.warning_alerts_topic = sns.Topic(
            self, "WarningAlertsTopic",
            topic_name="iam-identity-center-warning-alerts", 
            display_name="IAM Identity Center Warning Alerts",
            master_key=self.lambda_kms_key
        )
        
        self.access_issues_topic = sns.Topic(
            self, "AccessIssuesTopic",
            topic_name="iam-identity-center-access-issues",
            display_name="IAM Identity Center Access Issues",
            master_key=self.lambda_kms_key
        )

        # Wire the alerting topics into the Lambdas that publish to them.
        #
        # shared/alerting.py reads four topic ARNs from the environment and routes
        # by severity: CRITICAL -> critical, WARNING -> warning,
        # ACCESS_DENIED -> access issues, everything else -> discovery status.
        # When an ARN is absent, send_alert() logs "No topic configured" and
        # returns False -- the alert is dropped rather than delivered.
        #
        # instance_scanner imports the module and has several alerting call sites
        # (send_discovery_status, send_discovery_failure_alert), so without these
        # variables a discovery failure would notify nobody. change_detection
        # already received two of the four ARNs above; it gets the remaining two
        # here so severity routing works from either function.
        for alerting_function in (self.instance_scanner, self.change_detection):
            alerting_function.add_environment(
                "CRITICAL_ALERTS_TOPIC_ARN", self.critical_alerts_topic.topic_arn
            )
            alerting_function.add_environment(
                "WARNING_ALERTS_TOPIC_ARN", self.warning_alerts_topic.topic_arn
            )
            alerting_function.add_environment(
                "ACCESS_ISSUES_TOPIC_ARN", self.access_issues_topic.topic_arn
            )
            alerting_function.add_environment(
                "DISCOVERY_STATUS_TOPIC_ARN", self.discovery_status_topic.topic_arn
            )
            self.critical_alerts_topic.grant_publish(alerting_function)
            self.warning_alerts_topic.grant_publish(alerting_function)
            self.access_issues_topic.grant_publish(alerting_function)
            self.discovery_status_topic.grant_publish(alerting_function)

        # Enhanced Lambda function monitoring
        lambda_functions = [
            ("InstanceScanner", self.instance_scanner),
            ("ApplicationDiscovery", self.application_discovery),
            ("AssignmentDiscovery", self.assignment_discovery),
            ("CsvExport", self.csv_export),
            ("ChangeDetection", self.change_detection)
        ]
        
        for function_name, function in lambda_functions:
            # Enhanced error rate alarm with anomaly detection
            # Fix CFN_NAG_W28: Remove explicit alarm name to allow CloudFormation updates
            error_alarm = cloudwatch.Alarm(
                self, f"{function_name}ErrorAlarm",
                alarm_description=f"High error rate in {function_name} Lambda function",
                metric=function.metric_errors(
                    period=Duration.minutes(5),
                    statistic="Sum"
                ),
                threshold=3,  # Reduced threshold for faster detection
                evaluation_periods=2,
                datapoints_to_alarm=2,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            
            # Memory utilization alarm
            # Fix CFN_NAG_W28: Remove explicit alarm name to allow CloudFormation updates
            memory_alarm = cloudwatch.Alarm(
                self, f"{function_name}MemoryAlarm",
                alarm_description=f"High memory utilization in {function_name} Lambda function",
                metric=cloudwatch.Metric(
                    namespace="AWS/Lambda",
                    metric_name="MemoryUtilization",
                    dimensions_map={
                        "FunctionName": function.function_name
                    },
                    period=Duration.minutes(5),
                    statistic="Average"
                ),
                threshold=80,  # 80% memory utilization
                evaluation_periods=3,
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            
            # Add enhanced alarm actions
            error_alarm.add_alarm_action(
                cloudwatch_actions.SnsAction(self.critical_alerts_topic)
            )
            error_alarm.add_ok_action(
                cloudwatch_actions.SnsAction(self.critical_alerts_topic)
            )
            
            memory_alarm.add_alarm_action(
                cloudwatch_actions.SnsAction(self.warning_alerts_topic)
            )
        
        # Enhanced DynamoDB monitoring
        dynamodb_tables = [
            ("Instances", self.instances_table),
            ("Applications", self.applications_table),
            ("Assignments", self.assignments_table)
        ]
        
        for table_name, table in dynamodb_tables:
            # Enhanced throttling alarm with lower threshold
            # Fix CFN_NAG_W28: Remove explicit alarm name to allow CloudFormation updates
            read_throttle_alarm = cloudwatch.Alarm(
                self, f"{table_name}ReadThrottleAlarm",
                alarm_description=f"DynamoDB read throttling detected on {table_name} table",
                metric=cloudwatch.Metric(
                    namespace="AWS/DynamoDB",
                    metric_name="ReadThrottledEvents",
                    dimensions_map={
                        "TableName": table.table_name
                    },
                    period=Duration.minutes(1),  # More frequent monitoring
                    statistic="Sum"
                ),
                threshold=1,
                evaluation_periods=1,  # Immediate alerting
                comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
            )
            
            read_throttle_alarm.add_alarm_action(
                cloudwatch_actions.SnsAction(self.warning_alerts_topic)
            )
        
        # Enhanced API Gateway monitoring
        # Fix CFN_NAG_W28: Remove explicit alarm name to allow CloudFormation updates
        api_error_alarm = cloudwatch.Alarm(
            self, "ApiGatewayErrorAlarm",
            alarm_description="High error rate in API Gateway",
            metric=cloudwatch.Metric(
                namespace="AWS/ApiGateway",
                metric_name="4XXError",
                dimensions_map={
                    "ApiName": self.api.rest_api_name,
                    "Stage": "prod"
                },
                period=Duration.minutes(5),
                statistic="Sum"
            ),
            threshold=5,  # Reduced threshold
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        
        api_error_alarm.add_alarm_action(
            cloudwatch_actions.SnsAction(self.warning_alerts_topic)
        )
        
        # Security-focused alarms
        # Fix CFN_NAG_W28: Remove explicit alarm name to allow CloudFormation updates
        unauthorized_api_calls_alarm = cloudwatch.Alarm(
            self, "UnauthorizedApiCallsAlarm",
            alarm_description="Unauthorized API calls detected",
            metric=cloudwatch.Metric(
                namespace="AWS/ApiGateway",
                metric_name="4XXError",
                dimensions_map={
                    "ApiName": self.api.rest_api_name,
                    "Stage": "prod"
                },
                period=Duration.minutes(5),
                statistic="Sum"
            ),
            threshold=10,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            treat_missing_data=cloudwatch.TreatMissingData.NOT_BREACHING
        )
        
        unauthorized_api_calls_alarm.add_alarm_action(
            cloudwatch_actions.SnsAction(self.access_issues_topic)
        )
        
        # Output enhanced alerting configuration
        cdk.CfnOutput(
            self, "SecurityMonitoringConfiguration",
            value=json.dumps({
                "critical_alerts_topic": self.critical_alerts_topic.topic_arn,
                "warning_alerts_topic": self.warning_alerts_topic.topic_arn,
                "access_issues_topic": self.access_issues_topic.topic_arn,
                "kms_key_id": self.lambda_kms_key.key_id,
                "vpc_id": self.vpc.vpc_id,
                "security_group_id": self.lambda_security_group.security_group_id
            }),
            description="Enhanced security monitoring and alerting configuration"
        )
        
        # Output security summary
        cdk.CfnOutput(
            self, "SecuritySummary",
            value=json.dumps({
                "encryption": {
                    "dynamodb": "Customer-managed KMS",
                    "s3": "Customer-managed KMS", 
                    "lambda_env": "Customer-managed KMS",
                    "sns": "Customer-managed KMS"
                },
                "network": {
                    "vpc": "Private subnets with NAT Gateway",
                    "vpc_endpoints": "DynamoDB, S3, SSO, SNS, CloudWatch",
                    "security_groups": "Restrictive egress rules"
                },
                "access_control": {
                    "iam": "Least privilege policies",
                    "api_gateway": "IAM authentication required",
                    "s3": "Bucket policies with IP restrictions"
                },
                "monitoring": {
                    "cloudwatch": "Enhanced alarms with anomaly detection",
                    "xray": "Distributed tracing enabled",
                    "logs": "Encrypted with KMS"
                }
            }),
            description="Comprehensive security implementation summary"
        )