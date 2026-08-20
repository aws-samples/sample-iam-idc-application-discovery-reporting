# Automate IAM Identity Center governance with continuous discovery and reporting

This repository contains the sample solution that provides continuous visibility 
into AWS IAM Identity Center applications, user and group assignments, and access 
patterns across your organization, and lets you add near real-time enforcement of 
your assignment naming conventions.

The solution has two parts, each deployed as its **own independent CDK stack**
(in its own directory, with its own `cdk deploy`):

1. **Reporting** (baseline visibility) — a serverless, scheduled discovery
   pipeline that inventories IAM Identity Center instances, applications, and
   assignments, stores them in Amazon DynamoDB, and exposes on-demand CSV
   exports through a REST API. Lives in [`identity-center-reporting/`](./identity-center-reporting/)
   (Python CDK), stack `IamIdentityCenterDiscoveryStack-<env>`.
2. **Reactive monitoring** (optional enforcement) — an event-driven monitor
   that validates new assignments against your naming conventions in near real
   time and either notifies or auto-remediates non-compliant assignments. Lives
   in [`identity-center-remediation/`](./identity-center-remediation/)
   (TypeScript CDK), stack `IdentityCenterAppMonitorStack`.

> **These are two separate stacks, not one.** Deploying the reporting solution
> does **not** deploy reactive monitoring — it is a distinct CDK app you deploy
> separately with its own `cdk deploy`. The two stacks share no resources; they
> only read the same IAM Identity Center instance at runtime.

Deploy the reporting solution first for visibility, then opt in to reactive
monitoring when you're ready to enforce.

## Solutions

### [Reporting](./identity-center-reporting/) — baseline visibility

Automated discovery and inventory of IAM Identity Center resources with CSV
exports and API access.

- Scheduled daily discovery of instances, applications, and assignments
- Identity resolution — converts principal IDs to friendly user and group names
- CSV exports (applications, assignments, full dataset) over a REST API with
  time-limited presigned download URLs
- AWS Step Functions orchestration for reliable, incremental discovery
- Encryption at rest with customer-managed KMS keys, network isolation, and
  CloudWatch monitoring

**Stack**: AWS CDK (Python), Python 3.12 Lambda, Step Functions, DynamoDB, S3,
API Gateway

### [Reactive monitoring](./identity-center-remediation/) — optional enforcement

Event-driven monitoring that validates IAM Identity Center application
assignments against naming conventions and responds in near real time.

- Detects assignment events through Amazon EventBridge (within ~60 seconds)
- Validates that group names match application naming conventions
- Two modes: **notification** (default — alert only) and **auto-remediation**
  (delete non-compliant assignments)
- Organization-wide monitoring from a single deployment, with SNS alerting

**Stack**: AWS CDK (TypeScript), Python 3.12 Lambda, EventBridge, CloudTrail, SNS

## Prerequisites

- An AWS Organization with IAM Identity Center enabled
- A **delegated administration account** configured for IAM Identity Center
  (deploy here, not in the management account — this follows AWS security best
  practices for operational separation)
- AWS CLI configured with credentials for the delegated admin account
- Node.js 18+ and Python 3.12+
- AWS CDK CLI, pinned (`npm install -g aws-cdk@2.1128.0`) — the version this
  solution was validated with. An unpinned global install resolves to whatever
  is latest at install time.

> **Deploy in the delegated administration account**, not the management
> account.

Single-account discovery works with no further setup. Organization-wide discovery
additionally requires a cross-account discovery role in each member account —
deploy it with `identity-center-reporting/scripts/deploy-cross-account-roles.py`.
Until that role exists, the workflow still completes successfully and reports on
the account it runs in, so a first deployment is safe without it.

## Architecture

The two solutions are independent CDK stacks that share only the IAM Identity
Center instance they read at runtime. Each stack has its own architecture
diagram below. Editable source and high-resolution SVGs live in
[`docs/diagrams/`](./docs/diagrams/).

### Reporting stack — scheduled discovery and on-demand CSV exports

![Reporting architecture: an EventBridge daily rule and an API Gateway POST /trigger route start a Step Functions state machine that orchestrates the instance-scanner, application-discovery, assignment-discovery, change-detection, and access-tracker Lambdas inside a VPC. The Lambdas read IAM Identity Center, Identity Store, Organizations, and CloudTrail and write to five DynamoDB tables: instances, applications, assignments, discovery state (incremental checkpoints), and an append-only discovery change log. The csv-export Lambda reads DynamoDB, writes CSVs to an encrypted S3 bucket, and returns 15-minute presigned URLs through API Gateway. SNS, KMS customer-managed keys, and CloudWatch span the stack.](./docs/diagrams/reporting-architecture.png)

A daily Amazon EventBridge rule (and an on-demand `POST /trigger` API route)
starts an AWS Step Functions state machine that orchestrates the discovery
Lambdas inside a VPC. They inventory IAM Identity Center instances,
applications, and assignments — resolving friendly names from the Identity
Store and last-accessed data from CloudTrail — and write the results to five
DynamoDB tables. The IAM-authenticated REST API exposes CSV exports: the
`csv-export` Lambda reads DynamoDB, writes the file to the encrypted S3 bucket,
and returns a 15-minute presigned download URL.

### Reactive monitoring stack — event-driven naming-convention enforcement

![Reactive monitoring architecture: an IAM Identity Center assignment or profile change is recorded by CloudTrail; an EventBridge rule matches the sso.amazonaws.com management events and invokes the MonitorFunction Lambda. The Lambda resolves the application and group names from the Identity Store, validates the group name against the application naming convention, and either publishes an SNS notification or (in auto-remediation mode) calls DeleteApplicationAssignment and then alerts. Failed events go to an SQS dead-letter queue; a KMS key and encrypted CloudWatch Logs support the stack.](./docs/diagrams/remediation-architecture.png)

An assignment or profile change in IAM Identity Center is captured by CloudTrail
and matched by an Amazon EventBridge rule, which invokes the monitor Lambda
within roughly 60 seconds. The Lambda resolves the application and group names,
validates the group name against the application naming convention, and then
either publishes an SNS alert (notification mode) or deletes the non-compliant
assignment and alerts (auto-remediation mode). Events the Lambda fails to
process are captured in an SQS dead-letter queue.

## How the solution works

The solution has two independent paths that share the same IAM Identity Center
data: a **scheduled discovery pipeline** (reporting) that answers "what does my
environment look like?", and an **event-driven monitor** (reactive monitoring)
that answers "did someone just create a non-compliant assignment?".

### 1. Scheduled discovery (reporting)

An Amazon EventBridge rule (`iam-identity-center-daily-discovery`) triggers an
AWS Step Functions state machine once a day, at 02:00 UTC. The schedule does not
fire on deployment — to populate data immediately, trigger a run on demand with
the `POST /trigger` API route (see [Generate reports](#generate-reports)). The
state machine orchestrates the discovery Lambdas in three stages and writes
results to Amazon DynamoDB:

1. **Decide full vs. incremental.** The state machine first checks whether this
   run should be a full scan or an incremental one. Incremental runs (driven by
   the change-detection Lambda) only re-scan what changed since the last run,
   which keeps daily runs cheap; a full scan is forced on the first run or on
   demand with `{"force_full_discovery": true}`.

2. **Scan instances.** The *instance-scanner* Lambda calls
   `sso:ListInstances` (the `sso-admin` SDK client) across enabled Regions to find every IAM Identity
   Center instance in the organization. If none are found, the workflow exits
   cleanly. Discovered instances are written to the `…-instances` table.

3. **Discover applications.** A Step Functions `Map` state fans out the
   *application-discovery* Lambda across the instances, enumerating each
   instance's configured applications (managed and customer-managed) and their
   portal options. Results land in the `…-applications` table.

4. **Discover and enrich assignments.** A second `Map` state runs the
   *assignment-discovery* Lambda to map users and groups to applications. The
   *change-detection* Lambda diffs the new state against the previous run, and
   the *access-tracker* Lambda enriches each assignment with last-accessed data
   from CloudTrail (so you can answer "who used this application, and when?").
   The enriched records are written to the `…-assignments` table.

Throughout, principal IDs (GUIDs) are resolved to friendly user and group names
from the Identity Store, so the stored data and exports are human-readable.
Change notifications and run status are published to SNS topics.

### 2. Generating reports (reporting)

Reports are generated on demand from the data already in DynamoDB — querying the
API never calls IAM Identity Center directly, so it's fast and rate-limit safe.
The REST API (Amazon API Gateway, IAM-authenticated) exposes three export
routes, each backed by the *csv-export* Lambda:

| Route | Returns |
|-------|---------|
| `GET /export/applications` | All discovered applications |
| `GET /export/assignments`  | All user/group → application assignments, with friendly names |
| `GET /export/full`         | The combined dataset |

The Lambda writes a CSV to the encrypted Amazon S3 export bucket and returns a
**presigned download URL valid for 15 minutes** — the CSV itself is never sent
through the API response. A separate `POST /trigger` route lets you start a
discovery run on demand without waiting for the daily schedule.

### 3. Reactive monitoring (optional enforcement)

The reactive monitor watches IAM Identity Center **as changes happen**, rather
than once a day. An EventBridge rule (`identity-center-app-monitor-rule`)
matches CloudTrail events from `sso.amazonaws.com` for assignment and profile
changes and invokes the monitor Lambda within roughly 60 seconds of the change.
Two groups of events are matched:

- **Public API events** — `CreateApplicationAssignment`,
  `DeleteApplicationAssignment`, and `PutApplicationAssignmentConfiguration`.
  These are emitted by the `sso-admin` SDK and CLI and are listed in
  [CloudTrail events of IAM Identity Center API operations](https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html).
- **Console-plane profile events** — `AssociateProfile`, `DisassociateProfile`,
  `CreateProfile`, `UpdateProfile`, and `DeleteProfile`. These are not public API
  operations; they are emitted by the console APIs that IAM Identity Center
  relies on, so they capture changes made through the console UI.

`PutApplicationAssignmentConfiguration` is included because setting
`assignmentRequired` to `false` makes an application reachable by every user in
the identity store without any assignment existing — a governance bypass that
assignment-level checks alone would not catch.

Note that IAM Identity Center has no `UpdateApplicationAssignment` operation. An
assignment is a (principal, application) tuple, so changing one is a delete
followed by a create, both of which are matched above.

For each event the monitor Lambda:

1. Resolves the application name and the principal (group) name from the event,
   using the Identity Store and an optional `GroupNameRegex` to extract a
   friendly group name.
2. **Validates compliance** — by default it checks that the group name appears as
   a whole word in the application name. Matching is case-insensitive and splits
   both names on `-`, `_`, and whitespace, then requires one side's tokens to
   appear as a contiguous run of whole tokens in the other. This is deliberately
   not a substring match: group `read` must not satisfy application
   `sagemaker_readonly`, and a single-character group name must not satisfy every
   application containing that character. For example, group `Finance` assigned to application
   `Finance_PROD` is compliant; group `Finance` assigned to `HR_PROD` is not. Use
   the optional `GroupNameRegex` to extract a friendly portion of a longer group
   name (for example, `Finance` from `AWS-Finance-Admins`) before matching.
3. **Responds based on mode:**
   - **Notification mode** (`ENABLE_AUTO_DELETION=false`, the default) — publishes
     an SNS alert describing the non-compliant assignment and leaves it in place
     for a human to review.
   - **Auto-remediation mode** (`ENABLE_AUTO_DELETION=true`) — deletes the
     non-compliant assignment and publishes an SNS alert confirming the deletion.

A dead-letter queue captures any events the Lambda fails to process, and all
actions are logged to CloudWatch for an audit trail.

### Why two paths?

IAM Identity Center application ARNs use generated GUIDs, not friendly names,
which makes purely *preventative* IAM policies (for example, an SCP that denies
assignments to a specific application) difficult to express and maintain at
scale. This solution instead pairs **scheduled reporting** for baseline
visibility and audit with **event-driven detection and response** for near
real-time enforcement — historical analysis and immediate reaction, without
brittle name-based guardrails.

## Deploy

Always confirm you're authenticated to the intended (delegated administration)
account first:

```bash
aws sts get-caller-identity
```

### Deploy the reporting solution (baseline visibility)

The reporting solution is deployed with the AWS CDK. From the repository root:

```bash
# 1. Clone the solution repository
git clone https://github.com/aws-samples/sample-iam-idc-application-discovery-reporting.git
cd sample-iam-idc-application-discovery-reporting/identity-center-reporting

# 2. Create a virtualenv on Python 3.12 and install dependencies.
#    Use python3.12 explicitly, not bare `python3`: aws-cdk-lib requires >= 3.10,
#    and on macOS `python3` is still the system 3.9, where this install fails with
#    "No matching distribution found for aws-cdk-lib" rather than a version error.
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Bootstrap the CDK (if you haven't already in this account/Region)
cdk bootstrap aws://ACCOUNT-ID/REGION

# 4. (Optional) Validate before deploying: synthesize the template and run the tests
cdk synth
pip install -r tests/requirements-test.txt && python -m pytest tests

# 5. Generate the cross-account ExternalId. Required, no default — keep it, the
#    member-account roles must be deployed with the same value.
export IDC_EXTERNAL_ID="$(uuidgen)"

# 6. Deploy the solution. AllowedIpRange restricts API Gateway and presigned-URL
#    access — set it to your network's CIDR (default 0.0.0.0/0 allows all).
cdk deploy \
  --parameters AllowedIpRange=203.0.113.0/24 \
  --parameters CrossAccountExternalId="$IDC_EXTERNAL_ID"
```

The stack name is suffixed by the `CDK_ENVIRONMENT` variable (default `dev` →
`IamIdentityCenterDiscoveryStack-dev`). To deploy separate environments:

```bash
CDK_ENVIRONMENT=prod cdk deploy \
  --parameters AllowedIpRange=10.0.0.0/8 \
  --parameters CrossAccountExternalId="$IDC_EXTERNAL_ID"
```

Note the output values for the API Gateway URL and the Amazon S3 bucket name —
you use them when you generate reports. After deployment, the discovery pipeline
runs on a daily schedule (02:00 UTC); it does not run automatically on deployment,
so trigger the first run on demand with the `POST /trigger` route. See the
[reporting README](./identity-center-reporting/README.md) for how to verify the
deployment.

> This deploys the **reporting stack only**. Reactive monitoring is a separate
> stack — if you want enforcement, continue with the next section.

### Deploy the reactive monitoring solution (optional enforcement)

The reactive monitoring solution is a **separate AWS CDK (TypeScript) app** with
its own stack — deploying reporting does not deploy it. Deploy
it in **notification mode** first — it alerts on non-compliant assignments
without modifying them.

The stack needs two values at deploy time. Both can be resolved with the AWS
CLI from the delegated administration account:

- **IdentityCenterInstanceArn** — your IAM Identity Center instance ARN
- **ManagementAccountId** — the organization's **management account** ID
  (Identity Center application ARNs embed the management account, so this must
  be the management account — not the delegated admin account you deploy from)

```bash
cd ../identity-center-remediation   # from identity-center-reporting
npm install

INSTANCE_ARN=$(aws sso-admin list-instances \
  --query 'Instances[0].InstanceArn' --output text)
MGMT_ACCOUNT_ID=$(aws organizations describe-organization \
  --query 'Organization.MasterAccountId' --output text)

cdk deploy \
  --context enableAutoDeletion=false \
  --parameters IdentityCenterInstanceArn=$INSTANCE_ARN \
  --parameters ManagementAccountId=$MGMT_ACCOUNT_ID
```

Once you've validated the naming policies in notification mode, re-deploy with
`enableAutoDeletion=true` to have the monitor delete non-compliant assignments:

```bash
cdk deploy \
  --context enableAutoDeletion=true \
  --parameters IdentityCenterInstanceArn=$INSTANCE_ARN \
  --parameters ManagementAccountId=$MGMT_ACCOUNT_ID
```

> Start in notification mode and confirm the policies behave as expected before
> enabling auto-remediation.

### Validate the deployment

After `cdk deploy` completes, confirm the stack is healthy and the discovery
Lambdas can reach IAM Identity Center:

```bash
# 1. Stack status should be CREATE_COMPLETE or UPDATE_COMPLETE
aws cloudformation describe-stacks \
  --stack-name IamIdentityCenterDiscoveryStack-dev \
  --query 'Stacks[0].StackStatus'

# 2. The deploying credentials (and by extension the account) can list
#    Identity Center instances — the same API the Lambdas call
aws sso-admin list-instances --query 'Instances[].InstanceArn'

# 3. Trigger a first discovery run and confirm it succeeds
aws stepfunctions start-execution \
  --state-machine-arn $(aws stepfunctions list-state-machines \
    --query "stateMachines[?name=='iam-identity-center-discovery'].stateMachineArn" --output text) \
  --input '{"trigger":"manual","force_full_discovery":true}'
aws stepfunctions list-executions \
  --state-machine-arn $(aws stepfunctions list-state-machines \
    --query "stateMachines[?name=='iam-identity-center-discovery'].stateMachineArn" --output text) \
  --max-results 1 --query 'executions[0].status'

# 4. Data landed: table should be non-empty after the run completes
aws dynamodb scan --table-name iam-identity-center-instances \
  --select COUNT --query Count
```

If the execution fails, check the Lambda logs for `AccessDenied` errors — see
the [reporting README troubleshooting section](./identity-center-reporting/README.md#troubleshooting)
for the log groups to check.

## Generate reports

After deployment, the discovery pipeline runs on a daily schedule (02:00 UTC).
The schedule does not fire on deployment, so start the first run on demand with
the `POST /trigger` route (below), then use the REST API to generate on-demand
CSV exports. Replace `[API-ID]` with the API Gateway ID from the deployment
output and `[REGION]` with your AWS Region (for example, `us-east-1`):

The API uses IAM (SigV4) authorization, so requests must be signed. The
simplest way from a shell is [`awscurl`](https://github.com/okigan/awscurl)
(`pip install awscurl==0.44`), which signs requests with your current AWS
credentials:

```bash
# Start a discovery run on demand (e.g. right after deployment)
awscurl --service execute-api --region [REGION] -X POST \
  "https://[API-ID].execute-api.[REGION].amazonaws.com/prod/trigger"

# Export discovered applications as CSV
awscurl --service execute-api --region [REGION] \
  "https://[API-ID].execute-api.[REGION].amazonaws.com/prod/export/applications"
```

Alternatively, use the interactive helper, which reads the API URL from the
stack outputs and signs requests for you:

```bash
python identity-center-reporting/scripts/post-deployment/start_manual_discovery.py \
  --stack-name IamIdentityCenterDiscoveryStack-dev --region [REGION]
```

The export routes (`/export/applications`, `/export/assignments`,
`/export/full`) each return a JSON response with a presigned Amazon S3 URL valid
for 15 minutes. See the [reporting README](./identity-center-reporting/README.md)
for the full set of endpoints and CSV formats.

## Clean up

The reporting stack's VPC networking — one NAT gateway and five interface endpoints
across two subnets — bills by the hour whether or not a discovery run happens, on the
order of $105/month in us-east-1 with the stack idle (see
[How much does this cost to run?](./identity-center-reporting/README.md#testing--validation)).
To avoid those ongoing charges, delete the resources when you no longer need them:

```bash
# Reactive monitoring (if deployed)
cd ../identity-center-remediation   # from identity-center-reporting
cdk destroy

# Reporting
cd ../identity-center-reporting
cdk destroy IamIdentityCenterDiscoveryStack-dev
```

### Troubleshooting: reporting stack delete fails on the VPC

The reporting stack provisions a VPC (private subnets, NAT gateway, interface
endpoints) for the discovery Lambdas. On teardown, CloudFormation occasionally
reports `DELETE_FAILED` with a message like *"The routeTable '…' has
dependencies and cannot be deleted"* or *"The vpc '…' has dependencies and
cannot be deleted."* This is a resource-ordering race — the NAT gateway,
subnet/route-table associations, or Lambda-created elastic network interfaces
(ENIs) haven't fully released by the time CloudFormation tries to delete the VPC
networking. It is not caused by the solution itself.

To resolve it:

1. Wait a few minutes (Lambda ENIs can take 20+ minutes to be reaped) and simply
   re-run the delete — it often succeeds on the second attempt once the NAT
   gateway has finished deleting:

   ```bash
   aws cloudformation delete-stack --stack-name IamIdentityCenterDiscoveryStack-dev
   ```

2. If it still fails on the route table, clear the leftover dependency manually,
   then re-run the delete. Replace the IDs with those from the error message and
   `aws ec2 describe-route-tables` / `describe-subnets` output:

   ```bash
   # Disassociate the private-subnet route table from its subnets
   aws ec2 disassociate-route-table --association-id <rtbassoc-id>

   # Delete any orphaned subnets the VPC is still waiting on
   aws ec2 delete-subnet --subnet-id <subnet-id>

   # Re-run the stack delete
   aws cloudformation delete-stack --stack-name IamIdentityCenterDiscoveryStack-dev
   ```

3. Confirm nothing is left behind:

   ```bash
   aws ec2 describe-vpcs \
     --filters "Name=tag:aws:cloudformation:stack-name,Values=IamIdentityCenterDiscoveryStack-dev" \
     --query "Vpcs[].VpcId"
   ```

## Security

This solution deploys with AWS security controls including encryption at rest
with customer-managed KMS keys, encryption in transit (TLS 1.2+), least-
privilege IAM, network isolation for the discovery Lambdas, IAM authentication
on API Gateway, and CloudWatch/CloudTrail audit logging. Review the per-solution
READMEs for details before deploying in production.

### Data protection and your compliance obligations

This solution reads, stores, and exports **personal data** about the people in your
IAM Identity Center directory: user names, display names, email addresses, principal
identifiers, and a record of which applications each person can reach and when they
last used them. That data is written to DynamoDB tables, to CSV files in Amazon S3,
and to CloudWatch Logs in the account where you deploy it.

Under the [AWS shared responsibility model](https://aws.amazon.com/compliance/shared-responsibility-model/),
you are responsible for how that personal data is handled. Depending on where your
users are and which regimes apply to you, that can include the GDPR, the UK GDPR,
CCPA/CPRA, and sector-specific rules. Decide deliberately on at least:

- **Lawful basis and notice** — whether you may process this data and whether the
  people in the directory have been told.
- **Data residency** — which Region you deploy into. The solution stores and exports
  data in the deployment Region, and the access tracker reads CloudTrail across
  Regions.
- **Retention** — the CSV bucket expires objects after 30 days by lifecycle rule, but
  the DynamoDB tables retain records indefinitely, and enabling point-in-time
  recovery (the default) extends the recovery window for that data.
- **Access** — who can call the export API, and who can read the S3 bucket and the
  CloudWatch log groups.
- **Deletion** — how a deletion request is honoured across the tables, the exports,
  the change log, and PITR backups.

See [AWS compliance resources](https://aws.amazon.com/compliance/) and
[AWS data privacy](https://aws.amazon.com/compliance/data-privacy/). Nothing here is
legal advice.

### Security considerations for production

This is a **sample** optimized to deploy and demo out of the box. A threat
review surfaced the following deliberate tradeoffs — review and harden each
before any non-demo use:

- **Presigned URL exposure (`AllowedIpRange`).** The CSV export API and its
  presigned Amazon S3 download URLs carry personal data (user emails, display
  names). `AllowedIpRange` is a **required parameter with no default** — it used to
  default to `0.0.0.0/0`, which made a bare `cdk deploy` produce a stack whose
  exports were redeemable from any IP. On the API the CIDR sits alongside IAM
  authentication; on a presigned URL it is the only control left once the URL has
  been issued, since the URL is a bearer token in a query string. `0.0.0.0/0` is
  still accepted for demos, but it now has to be typed. **Set it to your
  corporate/VPN CIDR** for anything beyond a demo
  (`cdk deploy --parameters AllowedIpRange=10.0.0.0/8`).
- **Export scope.** Any principal with `execute-api:Invoke` can call
  `/export/full` and retrieve the entire organization's assignment data. Add
  per-caller authorization/scoping if you need tenant isolation.
- **Shared Lambda execution role.** The discovery Lambdas share one execution
  role with cross-account `AssumeRole` and broad DynamoDB/SNS/S3 permissions.
  Compromise of any one function inherits the full set. Split into
  per-function roles for a tighter blast radius.
- **DynamoDB as a trust anchor.** Discovery reads instance ARNs and account IDs
  back from DynamoDB to drive cross-account role assumption. Restrict write
  access to the governance tables. Point-in-time recovery is on by default
  (`-c enableDynamoDbPitr=false` opts out) so records can't be silently poisoned
  or destroyed.
- **Cross-account `ExternalId`.** `CrossAccountExternalId` is a required stack
  parameter with no default, and the same value must be given to
  `scripts/deploy-cross-account-roles.py`. It used to be the literal
  `iam-identity-center-discovery`, hardcoded here — which mitigated nothing:
  `sts:ExternalId` only prevents a third party from having the role act on their
  behalf while the value is unknown to them, and that one was published in this
  repository. Generate a unique value per deployment (`uuidgen` works); the stack
  and the deploy script both reject the previously published value.
- **Compliance verdict inputs.** Naming-convention checks compare Identity Store
  group display names against application names. A privileged Identity Store
  admin who renames a group can influence the verdict; treat Identity Store
  admin as part of the trust boundary.
- **Reactive monitoring** — see that solution's README for the auto-deletion
  fail-closed behavior, the EventBridge-source invocation guard, and the DLQ
  failure alarms, all of which matter when running in auto-remediation mode.

See [CONTRIBUTING](CONTRIBUTING.md) for how to report a security issue.

## Documentation

- **[Reporting README](./identity-center-reporting/README.md)** — discovery
  process, CSV exports, API endpoints, verification, and configuration
- **[Reactive monitoring README](./identity-center-remediation/README.md)** —
  enforcement modes, configuration, monitoring, and troubleshooting

## Security disclaimer

This is sample code intended to demonstrate the a discovery and reporting mechanism
for AWS IAM Identity Center applications. Review and adapt it to your organization's
security and compliance requirements before using it in production.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE)
file.
