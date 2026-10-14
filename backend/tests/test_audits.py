import os, json, asyncio
import boto3, pytest
from moto import mock_aws
from pydantic import ValidationError
from src.tools import Auditor, Inputs, CATALOG

def test_bounds():
    with pytest.raises(ValidationError): Inputs(limit=999)
    with pytest.raises(ValidationError): Inputs(days=0)
    with pytest.raises(ValidationError): Inputs(function_name='hello<script>')

@mock_aws
def test_unused_volumes_and_no_mutation(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    s=boto3.Session(region_name='us-east-1'); ec2=s.client('ec2')
    ec2.create_volume(AvailabilityZone='us-east-1a',Size=100,VolumeType='gp3')
    r=Auditor(s).call('find_unused_ebs_volumes')
    assert len(r['findings'])==1 and r['findings'][0]['estimated_monthly_savings']==8
    assert len(ec2.describe_volumes()['Volumes'])==1

@mock_aws
def test_iam_mfa_and_root(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    s=boto3.Session(region_name='us-east-1'); iam=s.client('iam')
    iam.create_user(UserName='engineer'); iam.create_login_profile(UserName='engineer',Password='test-password')
    r=Auditor(s).call('audit_iam_users'); assert r['findings'][0]['severity']=='HIGH'
    assert Auditor(s).call('get_root_account_status')['findings']

@mock_aws
def test_public_acl_blocked(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    s=boto3.Session(region_name='us-east-1'); c=s.client('s3'); c.create_bucket(Bucket='public-test-bucket'); c.put_bucket_acl(Bucket='public-test-bucket',ACL='public-read')
    assert len(Auditor(s).call('find_public_buckets')['findings'])==1
    c.put_public_access_block(Bucket='public-test-bucket',PublicAccessBlockConfiguration={'BlockPublicAcls':True,'IgnorePublicAcls':True,'BlockPublicPolicy':True,'RestrictPublicBuckets':True})
    assert not Auditor(s).call('find_public_buckets')['findings']

@mock_aws
def test_public_admin_port_ipv6(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    s=boto3.Session(region_name='us-east-1'); c=s.client('ec2'); v=c.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']['VpcId']; g=c.create_security_group(GroupName='ssh',Description='test',VpcId=v)['GroupId']
    c.authorize_security_group_ingress(GroupId=g,IpPermissions=[{'IpProtocol':'tcp','FromPort':22,'ToPort':22,'Ipv6Ranges':[{'CidrIpv6':'::/0'}]}])
    assert Auditor(s).call('check_open_security_groups')['findings']

def test_partial_coverage_has_no_score(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    a=Auditor(boto3.Session(region_name='us-east-1')); real=a.call
    from src.tools import result
    def call(name,**kwargs):
        if name=='generate_account_health_report': return real(name,**kwargs)
        return result('unavailable',errors=[{'tool':name,'code':'AccessDenied'}])
    monkeypatch.setattr(a,'call',call)
    r=a.call('generate_account_health_report'); assert r['data']['health_score'] is None and r['data']['coverage']=='partial'

def test_demo_all_tools(monkeypatch):
    monkeypatch.setenv('DEMO_MODE','true')
    for name in CATALOG:
        r=Auditor().call(name); assert set(['summary','findings','truncated','errors','data']).issubset(r)

@pytest.mark.parametrize('authorized',[True,False])
def test_lambda_mcp_and_auth(monkeypatch,authorized):
    monkeypatch.delenv('DEMO_MODE',raising=False); monkeypatch.setenv('MCP_TOKEN','test-token')
    from src import app
    app._secret=None
    event={'rawPath':'/mcp','rawQueryString':'','headers':{'host':'test.execute-api.us-east-1.amazonaws.com','content-type':'application/json','accept':'application/json, text/event-stream',**({'authorization':'Bearer test-token'} if authorized else {})},'requestContext':{'http':{'method':'POST'}},'body':json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-03-26','capabilities':{},'clientInfo':{'name':'test','version':'1'}}})}
    r=app.handler(event,None)
    assert r['statusCode']==(200 if authorized else 401)
    if authorized: assert json.loads(r['body'])['result']['serverInfo']['name']=='AWS Assistant'

def test_dashboard_requires_cognito(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    from src.app import handler
    r=handler({'rawPath':'/api/report','headers':{'host':'localhost','authorization':'Bearer test-token'},'requestContext':{'http':{'method':'GET'}}},None)
    assert r['statusCode']==401

@mock_aws
def test_scan_persists_and_cache(monkeypatch):
    monkeypatch.setenv('DEMO_MODE','true'); monkeypatch.setenv('SCAN_TABLE','scans')
    c=boto3.client('dynamodb',region_name='us-east-1');c.create_table(TableName='scans',BillingMode='PAY_PER_REQUEST',AttributeDefinitions=[{'AttributeName':'pk','AttributeType':'S'}],KeySchema=[{'AttributeName':'pk','KeyType':'HASH'}])
    monkeypatch.setenv('AWS_DEFAULT_REGION','us-east-1')
    from src.storage import scan_handler
    scan_handler({},None)
    assert c.get_item(TableName='scans',Key={'pk':{'S':'latest'}})['Item']['report']

def test_mcp_catalog_and_call_across_invocations(monkeypatch):
    monkeypatch.setenv('DEMO_MODE','true')
    from src.app import handler
    def rpc(method,params=None):
        e={'rawPath':'/mcp','headers':{'host':'localhost','accept':'application/json, text/event-stream','content-type':'application/json','mcp-protocol-version':'2025-03-26'},'requestContext':{'http':{'method':'POST'}},'body':json.dumps({'jsonrpc':'2.0','id':2,'method':method,'params':params or {}})}
        response=handler(e,None);assert response['statusCode']==200
        return json.loads(response['body'])['result']
    assert len(rpc('tools/list')['tools'])==18
    r=rpc('tools/call',{'name':'generate_account_health_report','arguments':{}})
    assert not r.get('isError')
    assert json.loads(r['content'][0]['text'])['data']['health_score']==60

def test_output_caps():
    from src.tools import result
    r=result('test',{'events':[{'message':'a'*10000} for _ in range(400)]})
    assert r['truncated'] and len(json.dumps(r).encode())<510000
