import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { IdentityCenterAppMonitorStack } from '../lib/identity-center-app-monitor-stack';

describe('IdentityCenterAppMonitorStack', () => {
  let app: cdk.App;
  let stack: IdentityCenterAppMonitorStack;
  let template: Template;

  beforeEach(() => {
    app = new cdk.App();
  });

  describe('Stack Synthesis', () => {
    test('synthesizes without errors', () => {
      // Test that stack can be created and synthesized
      expect(() => {
        stack = new IdentityCenterAppMonitorStack(app, 'TestStack', {
          enableAutoDeletion: false,
        });
        template = Template.fromStack(stack);
      }).not.toThrow();
    });
  });

  describe('Resource Creation', () => {
    beforeEach(() => {
      stack = new IdentityCenterAppMonitorStack(app, 'TestStack', {
        enableAutoDeletion: false,
      });
      template = Template.fromStack(stack);
    });

    test('creates SNS topic with correct properties', () => {
      template.hasResourceProperties('AWS::SNS::Topic', {
        DisplayName: 'Identity Center App Monitor Notifications',
        TopicName: 'identity-center-app-monitor-notifications',
      });
    });

    test('creates Lambda function with correct runtime and configuration', () => {
      template.hasResourceProperties('AWS::Lambda::Function', {
        FunctionName: 'identity-center-app-monitor',
        Runtime: 'python3.12',
        Handler: 'handler.lambda_handler',
        Timeout: 60,
        MemorySize: 256,
      });
    });

    test('creates CloudWatch Log Group with correct retention', () => {
      template.hasResourceProperties('AWS::Logs::LogGroup', {
        LogGroupName: '/aws/lambda/identity-center-app-monitor',
        RetentionInDays: 30,
      });
    });

    test('creates EventBridge rule with correct event pattern', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        EventPattern: {
          source: ['aws.sso'],
          'detail-type': ['AWS API Call via CloudTrail'],
          detail: {
            eventSource: ['sso.amazonaws.com'],
            eventName: [
              'CreateApplicationAssignment',
              'DeleteApplicationAssignment',
              'PutApplicationAssignmentConfiguration',
              'AssociateProfile',
              'DisassociateProfile',
              'CreateProfile',
              'UpdateProfile',
              'DeleteProfile',
            ],
          },
        },
      });
    });

    test('does not subscribe to UpdateApplicationAssignment, which is not a real API', () => {
      // IAM Identity Center has no UpdateApplicationAssignment operation -- an
      // assignment is a (principal, application) tuple, so a change is a delete
      // followed by a create. It appears in neither the Actions table of the
      // Service Authorization Reference nor the CloudTrail event list, so a rule
      // matching on it can never fire.
      const rules = template.findResources('AWS::Events::Rule');
      const eventNames = Object.values(rules).flatMap(
        (rule: any) => rule.Properties?.EventPattern?.detail?.eventName ?? []
      );
      expect(eventNames.length).toBeGreaterThan(0);
      expect(eventNames).not.toContain('UpdateApplicationAssignment');
    });

    test('subscribes to PutApplicationAssignmentConfiguration', () => {
      // assignmentRequired=false makes an application reachable by every user in
      // the identity store without any assignment existing, bypassing
      // assignment-level naming governance. The monitor must see it.
      const rules = template.findResources('AWS::Events::Rule');
      const eventNames = Object.values(rules).flatMap(
        (rule: any) => rule.Properties?.EventPattern?.detail?.eventName ?? []
      );
      expect(eventNames).toContain('PutApplicationAssignmentConfiguration');
    });

    test('creates all required resources', () => {
      // Verify all resources are created
      template.resourceCountIs('AWS::SNS::Topic', 1);
      template.resourceCountIs('AWS::Lambda::Function', 1);
      template.resourceCountIs('AWS::Logs::LogGroup', 1);
      template.resourceCountIs('AWS::Events::Rule', 1);
      template.resourceCountIs('AWS::IAM::Role', 1);
    });

    test('creates DLQ and Lambda-error alarms that notify the SNS topic', () => {
      // A silently-failing monitor stops enforcing compliance with no signal;
      // both alarms must exist and route to the notification topic.
      template.resourceCountIs('AWS::CloudWatch::Alarm', 2);

      // DLQ depth > 0 (events failed all retries)
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        MetricName: 'ApproximateNumberOfMessagesVisible',
        Namespace: 'AWS/SQS',
        ComparisonOperator: 'GreaterThanThreshold',
        Threshold: 0,
      });

      // Lambda errors >= 1 (catch failures before they reach the DLQ)
      template.hasResourceProperties('AWS::CloudWatch::Alarm', {
        MetricName: 'Errors',
        Namespace: 'AWS/Lambda',
        ComparisonOperator: 'GreaterThanOrEqualToThreshold',
        Threshold: 1,
      });

      // Both alarms must have an alarm action wired (the SNS topic)
      const alarms = template.findResources('AWS::CloudWatch::Alarm');
      Object.values(alarms).forEach((alarm: any) => {
        expect(alarm.Properties.AlarmActions).toBeDefined();
        expect(alarm.Properties.AlarmActions.length).toBeGreaterThan(0);
      });
    });

    test('creates stack outputs', () => {
      // Verify all outputs are present
      template.hasOutput('IdentityCenterInstanceArnOutput', {});
      template.hasOutput('SnsTopicArn', {});
      template.hasOutput('LambdaFunctionArn', {});
      template.hasOutput('EventBridgeRuleName', {});
      template.hasOutput('LogGroupName', {});
    });

    test('creates CloudFormation parameter for Identity Center Instance ARN', () => {
      template.hasParameter('IdentityCenterInstanceArn', {
        Type: 'String',
        AllowedPattern: '^arn:aws:sso:::instance/ssoins-[a-zA-Z0-9]+$',
      });
    });
  });

  describe('IAM Policies', () => {
    beforeEach(() => {
      stack = new IdentityCenterAppMonitorStack(app, 'TestStack', {
        enableAutoDeletion: false,
      });
      template = Template.fromStack(stack);
    });

    test('Lambda role has Identity Center API permissions', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Effect: 'Allow',
              Action: [
                'sso:DescribeApplication',
                'sso:DescribeApplicationAssignment',
                'sso:DeleteApplicationAssignment',
                'sso:ListApplications',
                'sso:DescribeInstance',
                'sso:ListInstances',
              ],
              Resource: '*',
              Condition: {
                StringEquals: {
                  'aws:PrincipalOrgID': Match.anyValue(),
                },
              },
            }),
          ]),
        },
      });
    });

    test('Lambda role has Identity Store API permissions', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Effect: 'Allow',
              Action: [
                'identitystore:DescribeGroup',
                'identitystore:DescribeUser',
              ],
              Resource: '*',
            }),
          ]),
        },
      });
    });

    test('Lambda role has SNS publish permissions', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Effect: 'Allow',
              Action: 'sns:Publish',
            }),
          ]),
        },
      });
    });

    test('Lambda role can use the KMS key to publish to the encrypted SNS topic', () => {
      // Regression: publishing to a KMS-encrypted SNS topic requires the caller
      // to hold kms:GenerateDataKey/Decrypt, otherwise Publish fails closed.
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Effect: 'Allow',
              Action: Match.arrayWith([
                'kms:Decrypt',
                'kms:GenerateDataKey*',
              ]),
            }),
          ]),
        },
      });
    });

    test('Lambda role has CloudWatch Logs permissions', () => {
      template.hasResourceProperties('AWS::IAM::Policy', {
        PolicyDocument: {
          Statement: Match.arrayWith([
            Match.objectLike({
              Effect: 'Allow',
              Action: [
                'logs:CreateLogGroup',
                'logs:CreateLogStream',
                'logs:PutLogEvents',
              ],
            }),
          ]),
        },
      });
    });
  });

  describe('Environment Variables', () => {
    test('passes ENABLE_AUTO_DELETION=false when disabled', () => {
      stack = new IdentityCenterAppMonitorStack(app, 'TestStack', {
        enableAutoDeletion: false,
      });
      template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
          Variables: {
            ENABLE_AUTO_DELETION: 'false',
            LOG_LEVEL: 'INFO',
          },
        },
      });
    });

    test('passes ENABLE_AUTO_DELETION=true when enabled', () => {
      stack = new IdentityCenterAppMonitorStack(app, 'TestStack', {
        enableAutoDeletion: true,
      });
      template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
          Variables: {
            ENABLE_AUTO_DELETION: 'true',
            LOG_LEVEL: 'INFO',
          },
        },
      });
    });

    test('passes SNS_TOPIC_ARN environment variable', () => {
      stack = new IdentityCenterAppMonitorStack(app, 'TestStack', {
        enableAutoDeletion: false,
      });
      template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::Lambda::Function', {
        Environment: {
          Variables: Match.objectLike({
            SNS_TOPIC_ARN: Match.anyValue(),
          }),
        },
      });
    });
  });

  describe('Optional Configuration Parameters', () => {
    test('uses custom log retention when provided', () => {
      stack = new IdentityCenterAppMonitorStack(app, 'TestStack', {
        enableAutoDeletion: false,
        logRetentionDays: 7,
      });
      template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::Logs::LogGroup', {
        RetentionInDays: 7,
      });
    });

    test('uses custom Lambda timeout when provided', () => {
      stack = new IdentityCenterAppMonitorStack(app, 'TestStack', {
        enableAutoDeletion: false,
        lambdaTimeout: 120,
      });
      template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::Lambda::Function', {
        Timeout: 120,
      });
    });

    test('uses custom Lambda memory when provided', () => {
      stack = new IdentityCenterAppMonitorStack(app, 'TestStack', {
        enableAutoDeletion: false,
        lambdaMemory: 512,
      });
      template = Template.fromStack(stack);

      template.hasResourceProperties('AWS::Lambda::Function', {
        MemorySize: 512,
      });
    });
  });

  describe('EventBridge Integration', () => {
    beforeEach(() => {
      stack = new IdentityCenterAppMonitorStack(app, 'TestStack', {
        enableAutoDeletion: false,
      });
      template = Template.fromStack(stack);
    });

    test('EventBridge rule targets Lambda function', () => {
      template.hasResourceProperties('AWS::Events::Rule', {
        Targets: Match.arrayWith([
          Match.objectLike({
            Arn: Match.anyValue(),
          }),
        ]),
      });
    });

    test('Lambda has permission to be invoked by EventBridge', () => {
      template.hasResourceProperties('AWS::Lambda::Permission', {
        Action: 'lambda:InvokeFunction',
        Principal: 'events.amazonaws.com',
      });
    });
  });
});
