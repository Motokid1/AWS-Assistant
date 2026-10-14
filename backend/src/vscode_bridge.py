"""Local stdio adapter for the deployed AWS MCP server. Never prints credentials."""
import argparse
import asyncio
import logging
import sys
from datetime import timedelta
import boto3
import httpx
import mcp.types as types
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server
from mcp.server.stdio import stdio_server

async def run(region: str, stack: str, profile: str | None):
    aws = boto3.Session(profile_name=profile, region_name=region)
    outputs = await asyncio.to_thread(
        aws.client('cloudformation').describe_stacks, StackName=stack)
    values = {item['OutputKey']: item['OutputValue']
              for item in outputs['Stacks'][0]['Outputs']}
    secret = await asyncio.to_thread(
        aws.client('secretsmanager').get_secret_value,
        SecretId=values['TokenSecretArn'])
    token = secret['SecretString']
    if not token:
        raise RuntimeError('Secrets Manager returned an empty token')
    server = Server('aws-assistant-local-bridge')
    async with httpx.AsyncClient(headers={'Authorization': 'Bearer ' + token}, timeout=60) as http_client, streamable_http_client(values['MCPUrl'], http_client=http_client) as (read, write, _):
        async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=45)) as remote:
            await remote.initialize()

            @server.list_tools()
            async def list_tools() -> list[types.Tool]:
                tools = []
                cursor = None
                while True:
                    result = await remote.list_tools(cursor=cursor)
                    tools.extend(result.tools)
                    cursor = result.nextCursor
                    if not cursor:
                        return tools

            @server.call_tool()
            async def call_tool(name: str, arguments: dict) -> types.CallToolResult:
                return await remote.call_tool(name, arguments)

            async with stdio_server() as (local_read, local_write):
                await server.run(local_read, local_write,
                                 server.create_initialization_options())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--stack', default='aws-assistant-mcp')
    parser.add_argument('--profile', default=None)
    args = parser.parse_args()
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    asyncio.run(run(args.region, args.stack, args.profile))

if __name__ == '__main__':
    main()

