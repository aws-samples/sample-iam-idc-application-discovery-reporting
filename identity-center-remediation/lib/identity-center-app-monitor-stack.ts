import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sns from 'aws-cdk-lib/aws-sns';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as cwActions from 'aws-cdk-lib/aws-cloudwatch-actions';
import { Construct } from 'constructs';
import * as path from 'path';
import { NagSuppressions } from 'cdk-nag';

export interface IdentityCenterAppMonitorStackProps extends cdk.StackProps {
  enableAutoDeletion: boolean;
  logRetentionDays?: number;
  lambdaTimeout?: number;
  lambdaMemory?: number;
}

/**
 * Map a day count onto a valid logs.RetentionDays value.
 *
 * CloudWatch Logs accepts only a fixed set of retention periods. Casting an
 * arbitrary number with `as logs.RetentionDays` defeats the enum: a value such
 * as 45 passes synth and then fails at deploy with an opaque CloudFormation
 * error. Validating here fails fast and names the values actually allowed.
 */
function toRetentionDays(days: number): logs.RetentionDays {
  const valid = Object.values(logs.RetentionDays).filter(
    (v): v is number => typeof v === 'number'
  );
  if (!valid.includes(days)) {
    throw new Error(
      `logRetentionDays must be one of ${valid.join(', ')} -- got ${days}.`
    );
  }
  return days as logs.RetentionDays;
}

export class IdentityCenterAppMonitorStack extends cdk.Stack {
  public readonly snsTopic: sns.Topic;
  public readonly lambdaFunction: lambda.Function;
  public readonly eventRule: events.Rule;
  public readonly logGroup: logs.LogGroup;
  public readonly identityCenterInstanceArnParameter: cdk.CfnParameter;
  public readonly kmsKey: kms.Key;
  public readonly deadLetterQueue: sqs.Queue;

  constructor(scope: Construct, id: string, props: IdentityCenterAppMonitorStackProps) {
    super(scope, id, props);

    // Create CloudFormation parameter for Identity Center Instance ARN
    this.identityCenterInstanceArnParameter = new cdk.CfnParameter(this, 'IdentityCenterInstanceArn', {
      type: 'String',
      description: 'ARN of the AWS Identity Center instance (e.g., arn:aws:sso:::instance/ssoins-xxxxxxxxxxxxxxxxxx)',
      allowedPattern: '^arn:aws:sso:::instance/ssoins-[a-zA-Z0-9]+$',
      constraintDescription: 'Must be a valid Identity Center instance ARN (format: arn:aws:sso:::instance/ssoins-xxxxxxxxxx)',
    });

    // Create CloudFormation parameter for Management Account ID
    const managementAccountIdParameter = new cdk.CfnParameter(this, 'ManagementAccountId', {
      type: 'String',
      description: 'AWS Account ID where Identity Center is hosted (management/delegated admin account)',
      allowedPattern: '^[0-9]{12}$',
      constraintDescription: 'Must be a valid 12-digit AWS Account ID',
    });

    // Create CloudFormation parameter for optional regex pattern
    const groupNameRegexParameter = new cdk.CfnParameter(this, 'GroupNameRegex', {
      type: 'String',
      description: 'Optional regex pattern to extract friendly group name from full group name (e.g., "^([^-]+)" to extract prefix before first dash). Leave empty to use default substring matching.',
      default: '',
    });

    // Default values for optional parameters
    const logRetentionDays = props.logRetentionDays ?? 30;
    const lambdaTimeout = props.lambdaTimeout ?? 60;
    const lambdaMemory = props.lambdaMemory ?? 256;

    // Create KMS key for encryption
    this.kmsKey = new kms.Key(this, 'EncryptionKey', {
      description: 'KMS key for Identity Center App Monitor encryption',
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Add key policy to allow CloudWatch Logs to use the key
    this.kmsKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'Allow CloudWatch Logs',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal(`logs.${cdk.Stack.of(this).region}.amazonaws.com`)],
      actions: [
        'kms:Encrypt',
        'kms:Decrypt',
        'kms:ReEncrypt*',
        'kms:GenerateDataKey*',
        'kms:CreateGrant',
        'kms:DescribeKey',
      ],
      resources: ['*'],
      conditions: {
        ArnLike: {
          'kms:EncryptionContext:aws:logs:arn': `arn:aws:logs:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:log-group:/aws/lambda/identity-center-app-monitor`,
        },
      },
    }));

    // Add key policy to allow SNS to use the key, scoped to this stack's
    // topic and account. The topic ARN is built from the static topic name
    // (not a Ref) to avoid a circular dependency between key and topic.
    const notificationTopicArn = cdk.Arn.format({
      service: 'sns',
      resource: 'identity-center-app-monitor-notifications',
    }, this);
    this.kmsKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'Allow SNS',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('sns.amazonaws.com')],
      actions: [
        'kms:Decrypt',
        'kms:GenerateDataKey',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'aws:SourceAccount': cdk.Stack.of(this).account,
          'kms:EncryptionContext:aws:sns:topicArn': notificationTopicArn,
        },
      },
    }));

    // CloudWatch alarms publish to the CMK-encrypted topic; the alarm service
    // (not SNS) is the caller that must generate a data key. Without this,
    // alarm notifications fail closed with "Failed to execute action" and the
    // operator is never alerted — exactly the silent failure the alarms exist
    // to prevent. Scoped to alarm publishes for this account's topic.
    this.kmsKey.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'Allow CloudWatch Alarms',
      effect: iam.Effect.ALLOW,
      principals: [new iam.ServicePrincipal('cloudwatch.amazonaws.com')],
      actions: [
        'kms:Decrypt',
        'kms:GenerateDataKey',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'aws:SourceAccount': cdk.Stack.of(this).account,
          'kms:EncryptionContext:aws:sns:topicArn': notificationTopicArn,
        },
      },
    }));

    // Create Dead Letter Queue for Lambda
    this.deadLetterQueue = new sqs.Queue(this, 'LambdaDLQ', {
      queueName: 'identity-center-app-monitor-dlq',
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: this.kmsKey,
      retentionPeriod: cdk.Duration.days(14),
      // Adds a queue policy denying any request where aws:SecureTransport is
      // false. Failed events can carry principal and application identifiers, so
      // they should never travel over a plaintext connection.
      enforceSSL: true,
    });

    // 10.2 Create SNS topic resource with encryption
    this.snsTopic = new sns.Topic(this, 'NotificationTopic', {
      displayName: 'Identity Center App Monitor Notifications',
      topicName: 'identity-center-app-monitor-notifications',
      masterKey: this.kmsKey,
    });

    // 10.5 Create CloudWatch Log Group with encryption
    this.logGroup = new logs.LogGroup(this, 'LambdaLogGroup', {
      logGroupName: `/aws/lambda/identity-center-app-monitor`,
      retention: toRetentionDays(logRetentionDays),
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      encryptionKey: this.kmsKey,
    });

    // 10.4 Create IAM role for Lambda
    const lambdaRole = new iam.Role(this, 'LambdaExecutionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      description: 'Execution role for Identity Center App Monitor Lambda',
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // Add Identity Center API permissions with organization condition
    lambdaRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'sso:DescribeApplication',
        'sso:DescribeApplicationAssignment',
        'sso:DeleteApplicationAssignment',
        'sso:ListApplications',
        // Resolve the Identity Store ID from the instance ARN. Assignment
        // CloudTrail events omit directoryId, so the handler looks it up here.
        'sso:DescribeInstance',
        'sso:ListInstances',
      ],
      resources: ['*'],
      conditions: {
        StringEquals: {
          'aws:PrincipalOrgID': '${aws:PrincipalOrgID}',
        },
      },
    }));

    // Add Identity Store API permissions
    lambdaRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'identitystore:DescribeGroup',
        'identitystore:DescribeUser',
      ],
      resources: ['*'],
    }));

    // Add SNS publish permission
    lambdaRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sns:Publish'],
      resources: [this.snsTopic.topicArn],
    }));

    // Publishing to the KMS-encrypted SNS topic requires the *caller* to
    // generate a data key. Without this the Publish call fails with
    // KMSAccessDenied and no notification is ever delivered.
    this.kmsKey.grantEncryptDecrypt(lambdaRole);

    // Add CloudWatch Logs permissions
    lambdaRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'logs:CreateLogGroup',
        'logs:CreateLogStream',
        'logs:PutLogEvents',
      ],
      resources: [this.logGroup.logGroupArn],
    }));

    // 10.3 Create Lambda function resource
    this.lambdaFunction = new lambda.Function(this, 'MonitorFunction', {
      functionName: 'identity-center-app-monitor',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'handler.lambda_handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda'), {
        exclude: [
          '*.pyc',
          '__pycache__',
          '.pytest_cache',
          '.hypothesis',
          'test_*.py',
          'pytest.ini',
        ],
      }),
      timeout: cdk.Duration.seconds(lambdaTimeout),
      memorySize: lambdaMemory,
      role: lambdaRole,
      logGroup: this.logGroup,
      environment: {
        ENABLE_AUTO_DELETION: props.enableAutoDeletion.toString(),
        SNS_TOPIC_ARN: this.snsTopic.topicArn,
        LOG_LEVEL: 'INFO',
        IDENTITY_CENTER_INSTANCE_ARN: this.identityCenterInstanceArnParameter.valueAsString,
        MANAGEMENT_ACCOUNT_ID: managementAccountIdParameter.valueAsString,
        GROUP_NAME_REGEX: groupNameRegexParameter.valueAsString,
      },
      environmentEncryption: this.kmsKey,
      description: 'Monitors Identity Center application assignments for naming compliance',
      deadLetterQueue: this.deadLetterQueue,
      reservedConcurrentExecutions: 10,
    });

    // 10.6 Create EventBridge rule
    this.eventRule = new events.Rule(this, 'IdentityCenterEventRule', {
      ruleName: 'identity-center-app-monitor-rule',
      description: 'Captures Identity Center application assignment and profile events',
      eventPattern: {
        source: ['aws.sso'],
        detailType: ['AWS API Call via CloudTrail'],
        detail: {
          eventSource: ['sso.amazonaws.com'],
          eventName: [
            // Public IAM Identity Center API events. These are emitted by the
            // sso-admin SDK/CLI and are listed in the IAM Identity Center
            // CloudTrail reference:
            // https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html
            'CreateApplicationAssignment',
            'DeleteApplicationAssignment',
            // PutApplicationAssignmentConfiguration toggles assignmentRequired.
            // Setting it to false makes the application reachable by every user
            // in the identity store without any assignment existing, which
            // bypasses assignment-level naming governance entirely. Alert on it.
            'PutApplicationAssignmentConfiguration',
            // Console-plane profile events. These are not public API operations
            // (there is no PutProfile/AssociateProfile in the API Reference);
            // they are emitted by the console APIs that IAM Identity Center
            // relies on, so they capture changes made through the console UI.
            'AssociateProfile',
            'DisassociateProfile',
            'CreateProfile',
            'UpdateProfile',
            'DeleteProfile',
          ],
        },
      },
    });

    // Add Lambda function as target
    this.eventRule.addTarget(new targets.LambdaFunction(this.lambdaFunction));

    // Operational alarms — a silently-failing monitor stops enforcing naming
    // compliance with no signal. Both alarms notify the SNS topic so an
    // operator finds out when the pipeline breaks rather than by noticing the
    // absence of expected notifications.
    const alarmAction = new cwActions.SnsAction(this.snsTopic);

    // Any messages in the DLQ mean events failed all async retries and are
    // no longer being processed. Retention is 14 days, so these expire —
    // and enforcement is lost — unless someone acts.
    const dlqAlarm = new cloudwatch.Alarm(this, 'DlqNotEmptyAlarm', {
      alarmDescription:
        'Identity Center App Monitor DLQ has messages: events failed processing and enforcement is degraded. Inspect the DLQ and reprocess.',
      metric: this.deadLetterQueue.metricApproximateNumberOfMessagesVisible({
        period: cdk.Duration.minutes(5),
        statistic: 'Maximum',
      }),
      threshold: 0,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    dlqAlarm.addAlarmAction(alarmAction);

    // Lambda errors catch failures before retries exhaust into the DLQ, so
    // an operator is alerted at first failure rather than after events expire.
    const errorAlarm = new cloudwatch.Alarm(this, 'MonitorErrorAlarm', {
      alarmDescription:
        'Identity Center App Monitor Lambda is erroring: compliance validation may not be running.',
      metric: this.lambdaFunction.metricErrors({
        period: cdk.Duration.minutes(5),
        statistic: 'Sum',
      }),
      threshold: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });
    errorAlarm.addAlarmAction(alarmAction);

    // 10.7 Add stack outputs
    new cdk.CfnOutput(this, 'IdentityCenterInstanceArnOutput', {
      value: this.identityCenterInstanceArnParameter.valueAsString,
      description: 'ARN of the Identity Center instance being monitored',
      exportName: 'IdentityCenterAppMonitor-InstanceArn',
    });

    new cdk.CfnOutput(this, 'ManagementAccountIdOutput', {
      value: managementAccountIdParameter.valueAsString,
      description: 'Management Account ID where Identity Center is hosted',
      exportName: 'IdentityCenterAppMonitor-ManagementAccountId',
    });

    // No exportName: GroupNameRegex is optional and defaults to empty. CloudFormation
    // rejects cross-stack exports of empty/whitespace values, so this stays a plain
    // (non-exported) stack output that is still visible in the console and CLI.
    new cdk.CfnOutput(this, 'GroupNameRegexOutput', {
      value: groupNameRegexParameter.valueAsString,
      description: 'Regex pattern for extracting friendly group names (empty = default substring matching)',
    });

    new cdk.CfnOutput(this, 'SnsTopicArn', {
      value: this.snsTopic.topicArn,
      description: 'ARN of the SNS topic for notifications',
      exportName: 'IdentityCenterAppMonitor-SnsTopicArn',
    });

    new cdk.CfnOutput(this, 'LambdaFunctionArn', {
      value: this.lambdaFunction.functionArn,
      description: 'ARN of the Lambda function',
      exportName: 'IdentityCenterAppMonitor-LambdaFunctionArn',
    });

    new cdk.CfnOutput(this, 'EventBridgeRuleName', {
      value: this.eventRule.ruleName,
      description: 'Name of the EventBridge rule',
      exportName: 'IdentityCenterAppMonitor-EventBridgeRuleName',
    });

    new cdk.CfnOutput(this, 'LogGroupName', {
      value: this.logGroup.logGroupName,
      description: 'Name of the CloudWatch Log Group',
      exportName: 'IdentityCenterAppMonitor-LogGroupName',
    });

    // Add CDK Nag suppressions for acceptable security findings
    NagSuppressions.addResourceSuppressions(
      lambdaRole,
      [
        {
          id: 'AwsSolutions-IAM5',
          reason: 'Wildcard permissions required for Identity Center and Identity Store APIs as they do not support resource-level permissions. Organization condition restricts access to org resources only.',
        },
        {
          id: 'AwsSolutions-IAM4',
          appliesTo: [
            'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
          ],
          reason: 'AWSLambdaBasicExecutionRole grants only CloudWatch Logs create/put for the function log group. A customer-managed equivalent would duplicate an AWS-maintained policy without narrowing access.',
        },
        {
          id: 'W12',
          reason: 'Wildcard permissions required for Identity Center and Identity Store APIs as they do not support resource-level permissions. Organization condition restricts access to org resources only.',
        },
      ],
      true
    );

    NagSuppressions.addResourceSuppressions(
      this.lambdaFunction,
      [
        {
          id: 'AwsSolutions-L1',
          reason: 'Using Python 3.12 which is the latest stable runtime at time of implementation.',
        },
        {
          id: 'W58',
          reason: 'Lambda function has CloudWatch Logs permissions via the execution role and explicit log group configuration.',
        },
        {
          id: 'W89',
          reason: 'Lambda function does not require VPC access as it only calls AWS APIs (Identity Center, SNS, CloudWatch Logs) which are accessible via public endpoints.',
        },
      ],
      true
    );
  }
}
