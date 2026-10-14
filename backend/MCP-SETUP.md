# MCP-only development and AWS deployment

React is paused. Use `mcp-template.yaml`, not the full `template.yaml`, for this path. The full-stack template is retained as a reference; it is not used in this workflow.

## What is deployed

- Python 3.12 MCP Lambda and API Gateway HTTPS `/mcp` endpoint.
- Separate scanner Lambda, daily EventBridge schedule and deduplicated async jobs.
- Read-only AWS inspection policy, distinct MCP/scanner IAM roles and automatic temporary role credentials.
- DynamoDB cache, reports and 90-day history; Secrets Manager-generated bearer token.
- Seven-day CloudWatch logs, scanner error alarm, encrypted SQS DLQ and SNS email summaries/failure alerts.
- Budget email alerts (not a spending cap), optional Cost Anomaly Detection monitor, Bedrock model permission for the advisor.

No EC2 instance, dashboard API/worker, Cognito user pool, frontend S3 bucket or CloudFront distribution is deployed by this template. EC2/RDS/S3/IAM resources are inspected, not required for hosting.

The MCP-only endpoint exposes 18 existing audit/diagnostic tools plus `request_account_scan` and `get_scan_status`. The bearer token is an operator credential: holders can read account audit data and queue scans, which can incur API usage charges. Tools never modify inspected AWS resources. OAuth is disabled for this initial MCP-only stack; Claude OAuth connectors are not enabled by this template.

## Source map and adding a tool

- `src/tools.py`: CATALOG, Pydantic Inputs, Auditor, pagination and AWS checks.
- `src/models.py`: validated bounded outputs and scoring.
- `src/app.py`: FastMCP tool registration, bearer authentication and Lambda HTTP adapter.
- `src/storage.py`: tool caching, scan reservation/status, snapshots and scanner handler.
- `mcp-template.yaml`: API, Lambdas, IAM and supporting services.
- `tests/`: mocked AWS behavior and MCP transport tests.

To add a tool: add its name/description to CATALOG, validate new fields in Inputs, implement the read call in Auditor._call, add an explicit registration branch in build_mcp if its signature differs from days/limit, and add the required read action to AuditPolicy in mcp-template.yaml. Add it to AUDITS only if it belongs in account-wide scans. Add a meaningful test with moto or a mocked SDK response. Rebuild and redeploy after code/IAM changes.

Example pattern inside Auditor._call (the complete working EBS tool already exists):

```python
elif name == 'find_unused_ebs_volumes':
    rows, cut = self.rows('ec2', 'describe_volumes', 'Volumes', p.limit,
                          errors=errors,
                          Filters=[{'Name': 'status', 'Values': ['available']}])
    for volume in rows:
        fs.append(finding('waste', 'MEDIUM', volume['VolumeId'],
                          'Unattached EBS volume',
                          'Review ownership and backups before manual deletion.'))
```

`describe_volumes` requires `ec2:DescribeVolumes`. Do not give the tool `ec2:DeleteVolume` just to suggest cleanup. Auditor._call returns the standard result after its branch.

## 1. Prerequisites and account

AWS CLI and SAM CLI are separate installations. The Python version in `aws --version` is bundled with AWS CLI; it does not determine the Lambda runtime.

If `sam` is not recognized, download and run the Windows x64 MSI from https://github.com/aws/aws-sam-cli/releases/latest/download/AWS_SAM_CLI_64_PY3.msi . Follow the installer, then close and reopen PowerShell (restart VS Code if using its terminal). Verify `sam --version`. If installation succeeded but PATH is stale, run `& "C:\Program Files\Amazon\AWSSAMCLI\bin\sam.cmd" --version`; refresh the terminal PATH with `$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')` and retry. Do not install SAM into the application virtual environment.

Install Docker Desktop (Linux containers). Start Docker. Node/React are unnecessary for this workflow. Python 3.12 is used for local tests; SAM container builds provide the deployment runtime independently of local Python.

```powershell
$projectRoot='D:\Projects - AI\Aws-Assistant'
$region='us-east-1'
$stackName='aws-assistant-mcp'
aws --version
sam --version
docker info
aws configure
aws sts get-caller-identity
```

Use your existing named/SSO profile if available. Configure `$env:AWS_PROFILE='your-profile'` for that case. Do not use root access keys. The deployment identity needs permission to create/manage the resources above and pass the specific Lambda execution roles. Lambda uses its execution roles, not your local long-lived keys. Review the template with your account administrator if deployment access is restricted.

Enable Cost Explorer in Billing. Verify model availability in your selected region if using Bedrock. Set EnableAnomalyMonitor=false if an appropriate service monitor already exists. Initial cost history/forecasts/anomalies may be unavailable.

## 2. Optional local tests

Use one existing Python 3.12 virtual environment, or create it inside backend:

```powershell
cd "$projectRoot\backend"
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q
```

Do not recreate an active environment. Dependencies can also be installed into your existing local development environment; deployed Lambda remains Python 3.12.

## 3. Deploy MCP infrastructure

```powershell
cd "$projectRoot\backend"
sam validate --lint --template-file mcp-template.yaml
sam build --use-container --template-file mcp-template.yaml --build-dir .aws-sam/mcp-build
sam deploy --guided --template-file .aws-sam/mcp-build/template.yaml --config-file samconfig-mcp.toml --stack-name $stackName --region $region --capabilities CAPABILITY_IAM
```

Enter your NotificationEmail, a MonthlyBudget alert amount, BedrockModelId (default amazon.nova-lite-v1:0), and EnableAnomalyMonitor=true/false. Approve IAM role creation. API Gateway routes have no IAM/JWT authorizer because the Lambda validates its Secrets Manager bearer token; this does not make MCP tool calls anonymous. `/health` is intentionally public.

These manual commands use an isolated `.aws-sam/mcp-build` artifact directory and `samconfig-mcp.toml`, preventing accidental deployment of the full React stack. Run each command separately and stop if it fails. Validation checks infrastructure syntax; build packages Python dependencies in a Linux Python 3.12 container; deploy uploads the package and creates resources through CloudFormation. Confirm the change set contains the MCP stack only. Confirm the SNS subscription email after deployment.

## 4. Read outputs and load token without printing it

```powershell
$outputs=aws cloudformation describe-stacks --stack-name $stackName --region $region --query 'Stacks[0].Outputs' --output json | ConvertFrom-Json
$values=@{}
$outputs | ForEach-Object {$values[$_.OutputKey]=$_.OutputValue}
$values.MCPUrl
Invoke-RestMethod "$($values.ApiUrl)/health"
$env:AWS_ASSISTANT_MCP_TOKEN=aws secretsmanager get-secret-value --secret-id $values.TokenSecretArn --region $region --query SecretString --output text
```

Do not store the token in source or send it to a chat. The token cache expires after 60 seconds. Secret rotation must be coordinated with updating client credentials.

## 5. Verify MCP before configuring an AI client

```powershell
$headers=@{
  Authorization="Bearer $env:AWS_ASSISTANT_MCP_TOKEN"
  Accept='application/json, text/event-stream'
  'MCP-Protocol-Version'='2025-03-26'
}
$initialize=@{jsonrpc='2.0';id=1;method='initialize';params=@{protocolVersion='2025-03-26';capabilities=@{};clientInfo=@{name='powershell-test';version='1.0'}}} | ConvertTo-Json -Depth 8
Invoke-RestMethod -Uri $values.MCPUrl -Method Post -Headers $headers -ContentType 'application/json' -Body $initialize
$echo=@{jsonrpc='2.0';id=2;method='tools/call';params=@{name='echo';arguments=@{}}} | ConvertTo-Json -Depth 8
Invoke-RestMethod -Uri $values.MCPUrl -Method Post -Headers $headers -ContentType 'application/json' -Body $echo
```

The endpoint uses stateless JSON Streamable HTTP. Authenticated GET /mcp returns 405 deliberately; use an MCP client or POST. A 401 means a missing/incorrect bearer token. Check MCP Lambda logs for other failures. Echo confirms transport, not AWS read permissions.

## 6. Connect Codex or VS Code

For Codex, merge into your existing user config.toml, replacing URL:

```toml
[mcp_servers.aws_assistant]
url = "YOUR_MCP_URL"
bearer_token_env_var = "AWS_ASSISTANT_MCP_TOKEN"
```

From the terminal with the token, run `codex mcp list` and `codex`. Other application processes must inherit the token environment at startup.

For VS Code Copilot's built-in MCP support, open MCP: Open User Configuration and merge:

```json
{"servers":{"aws_assistant":{"type":"http","url":"YOUR_MCP_URL","headers":{"Authorization":"Bearer ${env:AWS_ASSISTANT_MCP_TOKEN}"}}}}
```

Start VS Code from the token-bearing terminal after closing other VS Code processes. Use MCP: List Servers to start it, then enable its tools in the agent's tool picker. Codex inside VS Code uses the Codex configuration instead.

Prompts:

- Use aws_assistant's echo tool to test connectivity.
- Find unused EBS volumes; request refresh=true for a fresh read.
- Queue an account scan using request_account_scan. Keep the returned job ID.
- Check that job with get_scan_status. When it completes, get the stored account health report.
- Show active CloudWatch alarms and explain their findings.

Account-wide scans cover enabled regions and run asynchronously; prefer this over live=true on the health tool, which can exceed the API timeout. Standalone tools accept region. The scanner also runs nightly. AI client compatibility remains a live acceptance check.

## 7. Create optional sandbox resources, including IAM and EC2

These are test targets, not hosting dependencies. Use a dedicated sandbox. The fixture stack creates a private VPC/subnet, an unattached encrypted 1 GiB EBS volume, unassociated EIP, an unused permissive SSH security group, a private S3 bucket, permissionless console IAM user without MFA (password generated in Secrets Manager), erroring Python Lambda and custom alarm. It does not create an IAM access key. No account-wide S3 public-access blocks are disabled.

EBS/EIP/Secrets Manager resources and the optional EC2 instance incur charges. Set LaunchEC2=true only if you want a running private t3.micro for inventory testing. It has no public IP or internet route. The open security-group rule is detectable as a permissive rule, even though the private instance is not reachable from the internet. You do not need SSH or an EC2 key pair for these tests.

```powershell
$az=aws ec2 describe-availability-zones --region $region --query 'AvailabilityZones[0].ZoneName' --output text
aws cloudformation deploy `
  --template-file "$projectRoot\backend\mcp-fixtures.yaml" `
  --stack-name aws-assistant-mcp-fixtures `
  --region $region `
  --capabilities CAPABILITY_IAM `
  --parameter-overrides AvailabilityZone=$az SandboxAcknowledgement=I_ACCEPT_SANDBOX_FIXTURE_CHARGES LaunchEC2=false

$fixtureOutputs=aws cloudformation describe-stacks --stack-name aws-assistant-mcp-fixtures --region $region --query 'Stacks[0].Outputs' --output json | ConvertFrom-Json
$fixtures=@{}
$fixtureOutputs | ForEach-Object {$fixtures[$_.OutputKey]=$_.OutputValue}
$fixtures
```

To include the private EC2 instance, rerun the deployment with LaunchEC2=true. The AMI is resolved from AWS's Amazon Linux 2023 public SSM parameter. The deployment identity needs ssm:GetParameters for that resolution.

Generate log/metric evidence and an active alarm:

```powershell
aws lambda invoke --function-name $fixtures.FunctionName --region $region "$projectRoot\backend\fixture-response.json"
aws cloudwatch set-alarm-state --alarm-name $fixtures.Alarm --state-value ALARM --state-reason 'Intentional sandbox MCP test' --region $region
```

The fixture Lambda intentionally returns FunctionError. Wait for logs/metrics to appear. Manually assigned alarm state is temporary and normal evaluation can replace it.

Ask the AI to verify the exact fixture resource IDs with find_unused_ebs_volumes, find_unused_elastic_ips, audit_iam_users, check_open_security_groups, list_active_alarms, get_lambda_logs and get_lambda_metrics. If EC2 was enabled, verify list_running_resources includes InstanceId. The private bucket should not be reported as public. Old snapshots/keys cannot be backdated; costs/forecast/anomaly data need real history. Not every tool is a finding detector.

## 8. Evidence, updates and cleanup

Validate manually through your AI client: list the tools, run echo, call each applicable audit tool, compare returned resource IDs with the fixture outputs, and inspect coverage/errors. Queue a scan, poll its job ID until complete, then retrieve the stored report. Test unauthorized requests return 401. Cost/Bedrock calls and scans may incur charges. Billing history and model access affect their results; successful transport alone does not validate findings. Confirm SNS emails separately.

Updates: repeat the validate, build and deploy commands in section 3 after code or IAM changes, using the same stack and region. No frontend publication step is needed.

Follow MCP logs:

```powershell
sam logs --name $values.MCPFunction --region $region --tail
```

After testing, remove the fixture resources:

```powershell
aws cloudformation delete-stack --stack-name aws-assistant-mcp-fixtures --region $region
aws cloudformation wait stack-delete-complete --stack-name aws-assistant-mcp-fixtures --region $region
```

To remove the MCP application itself when no longer needed:

```powershell
sam delete --stack-name $stackName --region $region
```

Review deletion results; non-empty S3 buckets and external dependencies can prevent deletion. Secrets can have service deletion/recovery behavior. Do not assume stack deletion stops charges for unrelated AWS resources.

Local tests/template lint do not prove a deployed Lambda build, IAM access, actual fixture detections, emails or client compatibility. Record those after executing in your sandbox. No monthly price guarantee is made.

Verification on 8 October 2026: 63 backend tests passed on Python 3.12.15, with one third-party deprecation warning. Both MCP templates passed SAM lint; manual deployment commands replace the removed deployment scripts. Container build, cloud deployment, fixture detections and live AI client compatibility remain unverified.
