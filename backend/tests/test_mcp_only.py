import json
from src import app

def rpc(method,params=None,token='test-token'):
    event={'rawPath':'/mcp','headers':{'host':'localhost','content-type':'application/json','accept':'application/json, text/event-stream','mcp-protocol-version':'2025-03-26','authorization':'Bearer '+token},'requestContext':{'http':{'method':'POST'}},'body':json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params or {}})}
    return app.mcp_handler(event,None)

def test_mcp_only_scan_roundtrip(monkeypatch):
    monkeypatch.setenv('DEMO_MODE','true');monkeypatch.setenv('ENABLE_SCAN_TOOLS','true');monkeypatch.setenv('MCP_OAUTH_ENABLED','false')
    catalog=json.loads(rpc('tools/list')['body'])['result']['tools']
    assert len(catalog)==20
    job=json.loads(json.loads(rpc('tools/call',{'name':'request_account_scan','arguments':{}})['body'])['result']['content'][0]['text'])
    status=json.loads(json.loads(rpc('tools/call',{'name':'get_scan_status','arguments':{'job_id':job['job_id']}})['body'])['result']['content'][0]['text'])
    assert status['status']=='COMPLETED'
    report=json.loads(json.loads(rpc('tools/call',{'name':'generate_account_health_report','arguments':{}})['body'])['result']['content'][0]['text'])
    assert report['score']==98

def test_bearer_only_rejects_bad_token_without_oauth_lookup(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False);monkeypatch.setenv('MCP_TOKEN','test-token');monkeypatch.setenv('MCP_OAUTH_ENABLED','false');monkeypatch.setenv('SCAN_TABLE','must-not-query')
    monkeypatch.setattr(app,'_secret',None)
    from src import oauth
    monkeypatch.setattr(oauth,'verify_token',lambda *args: (_ for _ in ()).throw(AssertionError('OAuth must be disabled')))
    result=rpc('initialize',token='wrong')
    assert result['statusCode']==401 and 'resource_metadata' not in result['headers']['www-authenticate']
