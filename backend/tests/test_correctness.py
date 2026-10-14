"""Regressions for the pre-deployment correctness requirements."""
import json, threading, time
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock
import boto3, pytest
from botocore.exceptions import ClientError
from moto import mock_aws
from pydantic import ValidationError
from src.tools import Auditor, Inputs, AUDITS, finding
from src.models import AccountReport, result, bounded_response, serialized_size
from src import storage


def denied(op='Read'):
    return ClientError({'Error': {'Code': 'AccessDenied', 'Message': 'denied'}}, op)


@pytest.fixture
def db(monkeypatch):
    with mock_aws():
        monkeypatch.delenv('DEMO_MODE', raising=False)
        monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')
        monkeypatch.setenv('SCAN_TABLE', 'scans')
        client=boto3.client('dynamodb',region_name='us-east-1')
        client.create_table(TableName='scans',BillingMode='PAY_PER_REQUEST',AttributeDefinitions=[{'AttributeName':'pk','AttributeType':'S'}],KeySchema=[{'AttributeName':'pk','KeyType':'HASH'}])
        yield storage.table()


def report():
    return result('Account audit',{'health_score':100,'coverage':'complete','region':'us-east-1','estimated_monthly_savings':0,'tools':{'get_cost_breakdown':result('costs',{'services':[]}), 'get_cost_forecast':result('forecast',{'Total':{'Amount':'0'}}), 'find_cost_anomalies':result('anomalies',{'anomalies':[]})}})


def test_report_required_fields_survive_every_trim_stage():
    fs=[finding('security','HIGH','r'*10000,'t'*10000,'f'*10000) for _ in range(200)]
    r=report();r['findings']=fs;r['data']['huge']='\u4e2d'*200000;r['errors']=[{'tool':'x','code':'\u4e2d'*10000} for _ in range(200)]
    trimmed=bounded_response(r,max_bytes=10000)
    AccountReport.model_validate(trimmed)
    assert serialized_size(trimmed)<=10000
    assert trimmed['truncated'] and trimmed['summary']
    assert trimmed['score'] is None and trimmed['coverage']=='partial'
    assert 'health_score' in trimmed['data'] and 'coverage' in trimmed['data']


def test_snapshot_fits_whole_dynamodb_item():
    r=report(); r['findings']=[finding('security','HIGH','\u4e2d'*4096,'\u4e2d'*4096,'\u4e2d'*4096) for _ in range(200)]
    snap=storage.fit_snapshot(r)
    assert storage.item_size({'pk':'latest','report':snap})<=300000
    AccountReport.model_validate(snap)


def test_cache_skips_oversize_and_warns(db,caplog):
    r=result('logs',{'events':[]}); r['data']['large']='x'*310000
    assert not storage.write_cache('too-big','get_lambda_logs',r)
    assert 'cache_skipped_oversize' in caplog.text
    assert 'Item' not in db.get_item(Key={'pk':'too-big'})


@pytest.mark.parametrize('name,ttl',[('get_cost_breakdown',3600),('get_cost_forecast',3600),('find_cost_anomalies',3600),('get_free_tier_usage',900),('audit_iam_users',900)])
def test_cache_lifetime_by_tool(db,monkeypatch,name,ttl):
    monkeypatch.setattr(storage.time,'time',lambda:1000)
    storage.write_cache('cache-test',name,result('ok'))
    assert db.get_item(Key={'pk':'cache-test'})['Item']['ttl']==1000+ttl


def test_cache_hit_refresh_and_expiry(db,monkeypatch):
    monkeypatch.setattr(storage.time,'time',lambda:1000)
    call=Mock(side_effect=[result('first'),result('refreshed'),result('expired')])
    monkeypatch.setattr(storage,'Auditor',lambda:SimpleNamespace(call=call))
    assert storage.cached_call('echo')['summary']=='first'
    assert storage.cached_call('echo')['summary']=='first'
    assert call.call_count==1
    assert storage.cached_call('echo',refresh=True)['summary']=='refreshed'
    monkeypatch.setattr(storage.time,'time',lambda:1901)
    assert storage.cached_call('echo')['summary']=='expired'


def cost_data(name):
    return {'get_cost_breakdown':{'services':[]},'get_cost_forecast':{'Total':{'Amount':'0'}},'find_cost_anomalies':{'anomalies':[]}}.get(name,{})


def test_completed_scan_invalidates_all_old_cache_variants(db,monkeypatch):
    call=Mock(side_effect=lambda name,**kwargs:report() if name=='generate_account_health_report' else result('fresh '+str(call.call_count)))
    monkeypatch.setattr(storage,'Auditor',lambda:SimpleNamespace(call=call))
    old=storage.cached_call('echo',limit=5)
    assert storage.cached_call('echo',limit=5)==old
    response=storage.scan_handler({},None)
    assert response['status']=='COMPLETED'
    assert storage.cached_call('echo',limit=5)['summary']!=old['summary']
    assert storage.latest()['score']==100
    assert storage.scan_status(response['job_id'])['status']=='COMPLETED'


def test_mcp_report_defaults_to_stored_and_live_is_explicit(db,monkeypatch):
    db.put_item(Item={'pk':'latest','report':storage.encoded(report())})
    call=Mock(return_value=report())
    monkeypatch.setattr(storage,'Auditor',lambda:SimpleNamespace(call=call))
    assert storage.cached_call('generate_account_health_report')['score']==100
    call.assert_not_called()
    storage.cached_call('generate_account_health_report',live=True,refresh=True)
    assert call.call_count==1


def test_latest_read_is_strongly_consistent(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    t=Mock();t.get_item.return_value={'Item':{'report':report()}}
    monkeypatch.setattr(storage,'table',lambda:t)
    storage.latest();t.get_item.assert_called_once_with(Key={'pk':'latest'},ConsistentRead=True)


def test_dedupe_and_old_job_completion_does_not_release_new_lock(db,monkeypatch):
    now=int(time.time());monkeypatch.setattr(storage.time,'time',lambda:now)
    first,created=storage.reserve_scan(); assert created
    again,created=storage.reserve_scan(); assert not created and again['job_id']==first['job_id']
    monkeypatch.setattr(storage.time,'time',lambda:now+storage.SCAN_LEASE_SECONDS+1)
    assert storage.scan_status(first['job_id'])['status']=='FAILED'
    second,created=storage.reserve_scan();assert created
    storage.finish_job(first['job_id'],'FAILED')
    assert db.get_item(Key={'pk':'scan#status'})['Item']['job_id']==second['job_id']
    assert db.get_item(Key={'pk':'scan#status'})['Item']['status']=='QUEUED'


def test_scan_failure_is_pollable_and_unlocks(db,monkeypatch):
    def fail(*args,**kwargs): raise RuntimeError('failure')
    monkeypatch.setattr(storage,'Auditor',lambda:SimpleNamespace(call=fail))
    job,_=storage.reserve_scan()
    with pytest.raises(RuntimeError): storage.scan_handler({'job_id':job['job_id']},None)
    assert storage.scan_status(job['job_id'])['status']=='FAILED'
    assert storage.reserve_scan()[1]


def test_duplicate_delivery_does_not_run_audit(db,monkeypatch):
    call=Mock(return_value=report());monkeypatch.setattr(storage,'Auditor',lambda:SimpleNamespace(call=call))
    job,_=storage.reserve_scan();event={'job_id':job['job_id']}
    assert storage.scan_handler(event,None)['status']=='COMPLETED'
    assert storage.scan_handler(event,None)['status']=='IGNORED'
    assert call.call_count==1


def test_scan_request_invokes_once_and_returns_same_job(db,monkeypatch):
    monkeypatch.setenv('SCAN_FUNCTION','scanner')
    client=Mock();original=boto3.client
    monkeypatch.setattr(storage.boto3,'client',lambda service,*args,**kwargs:client if service=='lambda' else original(service,*args,**kwargs))
    first=storage.request_scan();second=storage.request_scan()
    assert first['job_id']==second['job_id'] and second['deduplicated']
    assert client.invoke.call_count==1


def test_all_audit_checks_execute_concurrently(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    a=Auditor(boto3.Session(region_name='us-east-1')); original=a.call
    barrier=threading.Barrier(len(AUDITS),timeout=10)
    def call(name,**kwargs):
        if name=='generate_account_health_report':return original(name,**kwargs)
        barrier.wait()
        return result('ok',cost_data(name))
    monkeypatch.setattr(a,'call',call)
    assert a.call('generate_account_health_report')['score']==100


def test_paginator_later_denial_keeps_earlier_rows(monkeypatch):
    a=Auditor(boto3.Session(region_name='us-east-1'))
    def pages(**kwargs):
        yield {'Volumes':[{'VolumeId':'one'}]}
        raise denied('DescribeVolumes')
    client=Mock();client.can_paginate.return_value=True;client.get_paginator.return_value.paginate.side_effect=pages
    monkeypatch.setattr(a,'client',lambda _:client)
    errors=[];rows,_=a.rows('ec2','describe_volumes','Volumes',errors=errors)
    assert rows[0]['VolumeId']=='one' and errors[0]['code']=='AccessDenied'


@mock_aws
def test_s3_subcheck_denial_does_not_discard_public_finding(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    s=boto3.Session(region_name='us-east-1');a=Auditor(s);c=a.client('s3')
    c.create_bucket(Bucket='test-public-bucket');c.put_bucket_acl(Bucket='test-public-bucket',ACL='public-read')
    monkeypatch.setattr(c,'get_bucket_policy_status',Mock(side_effect=denied()))
    r=a.call('find_public_buckets')
    assert len(r['findings'])==1 and r['errors'][0]['code']=='AccessDenied'


@mock_aws
def test_iam_subcheck_denial_keeps_mfa_finding(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    a=Auditor(boto3.Session(region_name='us-east-1'));c=a.client('iam')
    c.create_user(UserName='engineer');c.create_login_profile(UserName='engineer',Password='test-password')
    monkeypatch.setattr(c,'list_access_keys',Mock(side_effect=denied()))
    r=a.call('audit_iam_users')
    assert r['findings'][0]['title']=='Console user without MFA' and r['errors']


def test_snapshot_uses_independent_90_day_default(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    a=Auditor(boto3.Session(region_name='us-east-1'));now=datetime.now(timezone.utc)
    monkeypatch.setattr(a,'rows',lambda *args,**kwargs:([{'SnapshotId':'recent','StartTime':now-timedelta(days=40)},{'SnapshotId':'old','StartTime':now-timedelta(days=100)}],False))
    assert [f['resource'] for f in a.call('find_old_snapshots',days=1)['findings']]==['old']
    assert len(a.call('find_old_snapshots',older_than_days=30)['findings'])==2


@pytest.mark.parametrize('kwargs',[{'older_than_days':0},{'minutes_back':1441},{'hours_back':169}])
def test_new_time_inputs_are_bounded(kwargs):
    with pytest.raises(ValidationError):Inputs(**kwargs)


def test_lambda_time_windows_and_metric_partial_failure(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    a=Auditor(boto3.Session(region_name='us-east-1'));rows=Mock(return_value=([],False));monkeypatch.setattr(a,'rows',rows)
    before=datetime.now(timezone.utc)
    a.call('get_lambda_logs',function_name='checkout',minutes_back=15)
    log_start=rows.call_args.kwargs['startTime']/1000
    assert abs(log_start-(before-timedelta(minutes=15)).timestamp())<2
    client=Mock()
    def metrics(**kwargs):
        if kwargs['MetricName']=='Errors': raise denied()
        assert abs((kwargs['EndTime']-kwargs['StartTime']).total_seconds()-7200)<1
        return {'Datapoints':[{'Sum':3}]}
    client.get_metric_statistics.side_effect=metrics;monkeypatch.setattr(a,'client',lambda _:client)
    r=a.call('get_lambda_metrics',function_name='checkout',hours_back=2)
    assert 'Invocations' in r['data'] and 'Duration' in r['data'] and r['errors']


def test_rds_only_available_and_alarms_become_findings(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    a=Auditor(boto3.Session(region_name='us-east-1'))
    def rows(service,operation,key,*args,**kwargs):
        if service=='ec2': return [],False
        if service=='rds': return [{'DBInstanceIdentifier':'yes','DBInstanceStatus':'available'},{'DBInstanceIdentifier':'no','DBInstanceStatus':'stopped'}],False
        return [{'AlarmName':'checkout-errors'}],False
    monkeypatch.setattr(a,'rows',rows)
    assert [r['id'] for r in a.call('list_running_resources')['data']['rds']]==['yes']
    alarm=a.call('list_active_alarms')['findings'][0]
    assert alarm['category']=='observability' and alarm['severity']=='MEDIUM'
    original=a.call
    monkeypatch.setattr(a,'call',lambda name,**kwargs:original(name,**kwargs) if name in ('generate_account_health_report','list_active_alarms') else result('ok',cost_data(name)))
    assert a.call('generate_account_health_report')['score']==98


def test_missing_cost_data_marks_report_partial(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    a=Auditor(boto3.Session(region_name='us-east-1'));original=a.call
    monkeypatch.setattr(a,'call',lambda name,**kwargs:original(name,**kwargs) if name=='generate_account_health_report' else result('ok'))
    r=a.call('generate_account_health_report')
    assert r['coverage']=='partial' and r['score'] is None

@pytest.mark.parametrize('service,operation,key',[('s3','list_buckets','Buckets'),('iam','list_users','Users'),('iam','list_access_keys','AccessKeyMetadata'),('ec2','describe_instances','Reservations'),('ec2','describe_snapshots','Snapshots')])
def test_paginated_reads_consume_later_pages(monkeypatch,service,operation,key):
    a=Auditor(boto3.Session(region_name='us-east-1'))
    client=Mock();client.can_paginate.return_value=True
    client.get_paginator.return_value.paginate.return_value=[{key:[{'id':'first'}]},{key:[{'id':'second'}]}]
    monkeypatch.setattr(a,'client',lambda _:client)
    rows,cut=a.rows(service,operation,key,limit=2)
    assert [r['id'] for r in rows]==['first','second'] and not cut
    client.get_paginator.assert_called_once_with(operation)


def test_explicit_token_fallback_for_api_without_sdk_paginator(monkeypatch):
    a=Auditor(boto3.Session(region_name='us-east-1'));client=Mock();client.can_paginate.return_value=False
    client.meta.method_to_api_mapping={'get_cost_and_usage':'GetCostAndUsage'}
    client.meta.service_model.operation_model.return_value.input_shape.members={'NextPageToken':None}
    client.get_cost_and_usage.side_effect=[{'ResultsByTime':[{'day':'one'}],'NextPageToken':'next'},{'ResultsByTime':[{'day':'two'}]}]
    monkeypatch.setattr(a,'client',lambda _:client)
    rows,cut=a.rows('ce','get_cost_and_usage','ResultsByTime')
    assert len(rows)==2 and not cut
    assert client.get_cost_and_usage.call_args_list[1].kwargs['NextPageToken']=='next'


def test_list_limit_reports_truncation(monkeypatch):
    a=Auditor(boto3.Session(region_name='us-east-1'));client=Mock();client.can_paginate.return_value=True
    client.get_paginator.return_value.paginate.return_value=[{'Snapshots':[{'id':'one'},{'id':'two'}]}]
    monkeypatch.setattr(a,'client',lambda _:client)
    rows,cut=a.rows('ec2','describe_snapshots','Snapshots',limit=1)
    assert len(rows)==1 and cut


def test_mcp_time_parameter_schemas(monkeypatch):
    monkeypatch.setenv('DEMO_MODE','true')
    from src.app import handler
    event={'rawPath':'/mcp','headers':{'host':'localhost','content-type':'application/json','accept':'application/json, text/event-stream','mcp-protocol-version':'2025-03-26'},'requestContext':{'http':{'method':'POST'}},'body':json.dumps({'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}})}
    response=handler(event,None)
    assert response['statusCode']==200
    schemas={t['name']:t['inputSchema']['properties'] for t in json.loads(response['body'])['result']['tools']}
    assert 'minutes_back' in schemas['get_lambda_logs'] and 'days' not in schemas['get_lambda_logs']
    assert 'hours_back' in schemas['get_lambda_metrics'] and 'days' not in schemas['get_lambda_metrics']
    assert schemas['find_old_snapshots']['older_than_days']['default']==90
    assert schemas['generate_account_health_report']['live']['default'] is False

def test_authenticated_job_status_endpoint_and_missing_job(db,monkeypatch):
    from src.app import handler
    job,_=storage.reserve_scan()
    def event(job_id,claims):
        return {'rawPath':'/api/scan/'+job_id,'headers':{'host':'localhost'},'requestContext':{'http':{'method':'GET'},'authorizer':{'jwt':{'claims':claims}}}}
    assert handler(event(job['job_id'],{}),None)['statusCode']==401
    response=handler(event(job['job_id'],{'sub':'manager'}),None)
    assert response['statusCode']==200
    assert json.loads(response['body'])['job_id']==job['job_id']
    assert handler(event('00000000-0000-0000-0000-000000000000',{'sub':'manager'}),None)['statusCode']==404


def test_scan_queuing_failure_is_reported_as_failed(db,monkeypatch):
    monkeypatch.setenv('SCAN_FUNCTION','scanner')
    client=Mock();client.invoke.side_effect=denied('Invoke');original=boto3.client
    monkeypatch.setattr(storage.boto3,'client',lambda service,*args,**kwargs:client if service=='lambda' else original(service,*args,**kwargs))
    with pytest.raises(ClientError):storage.request_scan()
    current=db.get_item(Key={'pk':'scan#status'})['Item']
    assert storage.scan_status(current['job_id'])['status']=='FAILED'


def test_superseded_worker_cannot_publish_snapshot(db,monkeypatch):
    now=int(time.time());monkeypatch.setattr(storage.time,'time',lambda:now)
    job,_=storage.reserve_scan()
    def supersede(*args,**kwargs):
        monkeypatch.setattr(storage.time,'time',lambda:now+storage.SCAN_LEASE_SECONDS+1)
        replacement,created=storage.reserve_scan();assert created
        return report()
    monkeypatch.setattr(storage,'Auditor',lambda:SimpleNamespace(call=supersede))
    with pytest.raises(ClientError):storage.scan_handler({'job_id':job['job_id']},None)
    assert 'Item' not in db.get_item(Key={'pk':'latest'})
    assert db.get_item(Key={'pk':'scan#status'})['Item']['job_id']!=job['job_id']
