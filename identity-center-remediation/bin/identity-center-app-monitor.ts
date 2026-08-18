#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { IdentityCenterAppMonitorStack } from '../lib/identity-center-app-monitor-stack';

const app = new cdk.App();

// Get configuration from context (optional parameters).
//
// CDK passes `-c key=value` through as a STRING. Handing that straight to a
// numeric CDK prop fails at synth with errors like
// `retentionInDays: "90" should be a number`, so every numeric context value is
// coerced and validated here. Invalid input fails fast with a message naming the
// offending value, rather than surfacing as an opaque CloudFormation error at
// deploy time.
const numericContext = (key: string): number | undefined => {
  const raw = app.node.tryGetContext(key);
  if (raw === undefined || raw === null || raw === '') {
    return undefined;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(
      `Context value '${key}' must be a positive whole number, got '${raw}'.`
    );
  }
  return value;
};

const enableAutoDeletion = app.node.tryGetContext('enableAutoDeletion') === 'true' ||
                          app.node.tryGetContext('enableAutoDeletion') === true;
const logRetentionDays = numericContext('logRetentionDays');
const lambdaTimeout = numericContext('lambdaTimeout');
const lambdaMemory = numericContext('lambdaMemory');

// Required stack parameters:
// - identityCenterInstanceArn: ARN of the Identity Center instance
// - managementAccountId: AWS Account ID where Identity Center is hosted
// Pass via: cdk deploy --parameters IdentityCenterInstanceArn=arn:aws:sso:::instance/ssoins-xxx --parameters ManagementAccountId=123456789012

new IdentityCenterAppMonitorStack(app, 'IdentityCenterAppMonitorStack', {
  enableAutoDeletion,
  logRetentionDays,
  lambdaTimeout,
  lambdaMemory,
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  description: 'Monitors AWS Identity Center application assignments for naming compliance',
});

// Run the cdk-nag AwsSolutions rule pack. The stack registers
// NagSuppressions, but without applying the Aspect no rule ever evaluates and
// those suppressions silently suppress nothing.
cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

app.synth();
