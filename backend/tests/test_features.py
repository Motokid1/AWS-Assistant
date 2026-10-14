import json,time
from unittest.mock import Mock
import boto3,pytest
from moto import mock_aws
from starlette.testclient import TestClient
from src import app,oauth,storage,demo
from src.models import result,WEIGHTS
from src.tools import Auditor

@pytest.fixture
def db(monkeypatch):
 with mock_aws():
  monkeypatch.delenv('DEMO_MODE',raising=False)
  monkeypatch.setenv('SCAN_TABLE','scans')
  boto3.client('dynamodb').create_table(TableName='scans',BillingMode='PAY_PER_REQUEST',AttributeDefinitions=[{'AttributeName':n,'AttributeType':'S'} for n in ('pk','kind','sort')],KeySchema=[{'AttributeName':'pk','KeyType':'HASH'}],GlobalSecondaryIndexes=[{'IndexName':'kind-index','KeySchema':[{'AttributeName':'kind','KeyType':'HASH'},{'AttributeName':'sort','KeyType':'RANGE'}],'Projection':{'ProjectionType':'ALL'}}])
  yield storage.table()

def event(path,method='POST',groups='viewer',body=''):
 return {'rawPath':path,'headers':{'host':'localhost','content-type':'application/json'},'requestContext':{'http':{'method':method},'authorizer':{'jwt':{'claims':{'sub':'user','cognito:groups':groups}}}},'body':body}

def test_viewer_cannot_scan_or_register(monkeypatch):
 monkeypatch.delenv('DEMO_MODE',raising=False)
 for path in ('/api/scan','/api/connections'):
  assert app.dashboard_handler(event(path),None)['statusCode']==403

def test_admin_can_queue_scan(monkeypatch):
 monkeypatch.delenv('DEMO_MODE',raising=False)
 monkeypatch.setattr(app,'request_scan',lambda cid:{'job_id':'test','status':'QUEUED'})
 assert app.dashboard_handler(event('/api/scan',groups='["admin"]'),None)['statusCode']==202

def test_body_limit(monkeypatch):
 monkeypatch.setenv('DEMO_MODE','true')
 assert app.handler(event('/api/scan',body='x'*65537),None)['statusCode']==413
 with TestClient(app.wrap(app.build_core(mode='dashboard'))) as client:
  assert client.post('/api/scan',content='x'*65537).status_code==413

def test_secret_rotation_without_cold_start(monkeypatch):
 monkeypatch.setattr(app,'_secret',None);monkeypatch.delenv('MCP_TOKEN',raising=False);monkeypatch.setenv('TOKEN_SECRET','secret')
 client=Mock();client.get_secret_value.side_effect=[{'SecretString':'first'},{'SecretString':'second'}]
 monkeypatch.setattr(app.boto3,'client',lambda _:client)
 clock=[100];monkeypatch.setattr(app.time,'monotonic',lambda:clock[0])
 assert app.token()=='first';clock[0]=159;assert app.token()=='first';clock[0]=161;assert app.token()=='second'

def test_demo_score_and_rescan_are_computed():
 before=demo.report();assert before['score']==100-sum(WEIGHTS[f['severity']] for f in before['findings'])
 demo.rescan();assert demo.report()['score']==98 and len(demo.history())==2
 demo.reset();assert demo.report()['score']==60

def test_oauth_metadata_registration_and_pkce_replay(db):
 with TestClient(app.wrap(app.build_core())) as client:
  metadata=client.get('/.well-known/oauth-authorization-server').json();assert metadata['code_challenge_methods_supported']==['S256']
  assert client.post('/oauth/register',json={'redirect_uris':['http://evil.example/cb']}).status_code==400
  registered=client.post('/oauth/register',json={'redirect_uris':['https://client.example/cb']});assert registered.status_code==201
  cid=registered.json()['client_id'];verifier='a'*64;resource='http://testserver/mcp'
  record={'client_id':cid,'redirect_uri':'https://client.example/cb','challenge':oauth.challenge(verifier),'resource':resource,'sub':'user'}
  oauth.put('oauth#code#'+oauth.digest('code'),record,120)
  args={'grant_type':'authorization_code','client_id':cid,'redirect_uri':record['redirect_uri'],'resource':resource,'code':'code','code_verifier':'b'*64}
  assert client.post('/oauth/token',data=args).status_code==400
  args['code_verifier']=verifier;args['resource']='https://other/mcp';assert client.post('/oauth/token',data=args).status_code==400
  args['resource']=resource;r=client.post('/oauth/token',data=args);assert r.status_code==200
  token=r.json()['access_token'];assert oauth.verify_token(token,resource) and not oauth.verify_token(token,'https://other/mcp')
  assert client.post('/oauth/token',data=args).status_code==400
  assert token not in json.dumps(storage.plain(db.get_item(Key={'pk':'oauth#token#'+oauth.digest(token)})['Item']))

def test_connection_allowlist_external_id_and_assume(db,monkeypatch):
 from src import connections
 role='arn:aws:iam::123456789012:role/audit'
 monkeypatch.setenv('ALLOWED_ROLE_ARNS',role)
 with pytest.raises(ValueError):connections.create_connection({'name':'wrong','role_arn':role+'bad'})
 row=connections.create_connection({'name':'Customer','role_arn':role});assert len(row['external_id'])>=32
 assert 'external_id' not in connections.connections()[0]
 sts=Mock();sts.assume_role.return_value={'Credentials':{'AccessKeyId':'test','SecretAccessKey':'test','SessionToken':'test'}}
 monkeypatch.setattr(connections.boto3,'client',lambda _:sts)
 connections.session_for(row['id'],'us-west-2')
 assert sts.assume_role.call_args.kwargs['ExternalId']==row['external_id']

def test_history_is_account_scoped_and_ordered(db):
 for i in range(3):db.put_item(Item={'pk':str(i),'kind':'history','sort':str(i),'report':{'score':i}})
 db.put_item(Item={'pk':'other','kind':'history#customer','sort':'4','report':{'score':50}})
 assert storage.report_history(2)==[{'score':1},{'score':2}]
 assert storage.report_history(2,'customer')==[{'score':50}]

def test_bedrock_converse_real_path(monkeypatch):
 monkeypatch.delenv('DEMO_MODE',raising=False);monkeypatch.setenv('BEDROCK_MODEL_ID','amazon.nova-lite-v1:0')
 auditor=Auditor(boto3.Session());client=Mock();client.converse.return_value={'output':{'message':{'content':[{'text':'Review idle EC2.'}]}},'usage':{'inputTokens':10}}
 monkeypatch.setattr(auditor,'client',lambda _:client)
 r=auditor.call('explain_aws_service',service_name='EC2',question='How do I reduce cost?')
 assert r['data']['explanation']=='Review idle EC2.' and client.converse.call_args.kwargs['modelId']=='amazon.nova-lite-v1:0'

def test_all_region_global_once_and_regional_findings(monkeypatch):
 from src.tools import AUDITS,Inputs,finding
 monkeypatch.delenv('DEMO_MODE',raising=False)
 with mock_aws():
  a=Auditor(boto3.Session(region_name='us-east-1'));ec2=Mock();ec2.describe_regions.return_value={'Regions':[{'RegionName':'us-east-1'},{'RegionName':'us-west-2'}]}
  monkeypatch.setattr(a,'client',lambda _:ec2)
  calls=[]
  def call(self,name,**kw):
   calls.append((name,self.session.region_name))
   data={'services':[]} if name=='get_cost_breakdown' else {'Total':{'Amount':'0'}} if name=='get_cost_forecast' else {'anomalies':[]} if name=='find_cost_anomalies' else {}
   return result(name,data,[finding('security','HIGH','sg','Open SSH','Restrict ingress')] if name=='check_open_security_groups' else [])
  monkeypatch.setattr(Auditor,'call',call)
  report=a.all_region_report(Inputs())
  assert report['coverage']=='complete' and report['score']==84
  assert sum(n=='audit_iam_users' for n,r in calls)==1
  assert {f['resource'] for f in report['findings']}=={'us-east-1:sg','us-west-2:sg'}
