# VS Code MCP setup

The project now includes `.vscode/mcp.json`, which VS Code loads when this project is open. It uses the VS Code `servers` key and workspace-relative paths. The root `mcp.json` uses `mcpServers` for other clients; do not paste that file into VS Code user configuration. See https://code.visualstudio.com/docs/agents/reference/mcp-configuration.

After changing configuration or bridge code, run `Developer: Reload Window`, then `MCP: List Servers` and start `aws_assistant`. Enable its tools in Copilot Agent mode. If a user entry also exists, use one active instance of the server.

The bridge requires the configured stack in the selected region and local permission to read CloudFormation outputs and the token secret. It limits remote MCP response waits to 45 seconds so gateway errors cannot leave tool calls waiting indefinitely. AWS inspection requests use bounded network timeouts; incomplete checks remain explicit errors. S3 bucket inspections run concurrently to reduce HTTP API latency. All-region scans process up to three regions at a time and close regional clients to fit the scanner's memory limit.

Install regression dependencies with `.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt`, then run `.\.venv\Scripts\python.exe -m pytest -q`. A successful tool call can contain account data limitations in `errors`, such as Cost Explorer `DataUnavailableException`; inspect those before interpreting findings.

Use the stdio bridge when VS Code's direct HTTP connection enters OAuth fallback. The bridge fetches the bearer token privately using the default local AWS profile, connects to the deployed Lambda, and forwards MCP tools. No Lambda redeployment is needed for this module. CloudFormation DescribeStacks and Secrets Manager GetSecretValue on the stack secret are required locally; full administrator access is unnecessary for the bridge.

1. Verify aws sts get-caller-identity.
2. In backend, create a Python 3.12 environment if none exists: py -3.12 -m venv .venv. Do not recreate an active environment.
3. Install dependencies: .\.venv\Scripts\python.exe -m pip install -r requirements.txt.
4. In VS Code MCP: Open User Configuration, replace the aws_assistant HTTP entry with the configuration in VS-CODE-CONFIG.json. Preserve unrelated servers. Remove this server's old token input if unused. This JSON is a reference, not automatically loaded from this directory.
5. MCP: List Servers > aws_assistant > Start. No token or OAuth prompt is required. Enable tools in local Copilot Agent chat and ask to call echo.
6. Ask find_unused_ebs_volumes with region us-east-1 and refresh true. Inspect errors and coverage; empty findings can be valid.
7. Request an account scan, retain job_id, poll get_scan_status until completed, then generate_account_health_report with live false.

A named AWS profile can be passed by adding --profile and its name to args. SSO profiles require aws sso login --profile NAME first. Stop/start the bridge after secret rotation or renewed credentials; it reads the secret at startup. An already running bridge keeps its token until restarted.

Live evidence: direct Lambda initialize, tools/list (20 tools), echo passed. SDK stdio-client -> local bridge -> deployed Lambda tools/list and echo passed. VS Code UI and every live audit check are not verified by these tests. Existing HTTP fallback's precise cause remains unresolved; the bridge avoids that path. No zero-bug guarantee is made.
