from concurrent.futures import ThreadPoolExecutor
import threading
from datetime import datetime, timezone
import boto3
from moto import mock_aws
from src.tools import Auditor

@mock_aws
def test_aws_clients_have_bounded_network_timeouts():
    config=Auditor(boto3.Session(region_name='us-east-1')).client('s3').meta.config
    assert config.connect_timeout==2
    assert config.read_timeout==5
    assert config.retries['total_max_attempts']==1

def test_s3_bucket_checks_run_concurrently(monkeypatch):
    monkeypatch.delenv('DEMO_MODE',raising=False)
    barrier=threading.Barrier(2)
    class S3:
        def get_public_access_block(self,**kwargs):
            barrier.wait(timeout=3)
            return {'PublicAccessBlockConfiguration':{}}
        def get_bucket_policy_status(self,**kwargs):
            return {'PolicyStatus':{'IsPublic':True}}
        def get_bucket_acl(self,**kwargs):
            return {'Grants':[]}
    class STS:
        def get_caller_identity(self): return {'Account':'123456789012'}
    class Control:
        def get_public_access_block(self,**kwargs): return {}
    auditor=Auditor()
    clients={'s3':S3(),'sts':STS(),'s3control':Control()}
    monkeypatch.setattr(auditor,'client',lambda name:clients[name])
    monkeypatch.setattr(auditor,'rows',lambda *args,**kwargs:([{'Name':'one'},{'Name':'two'}],False))
    response=auditor.call('find_public_buckets')
    assert not response['errors']
    assert {f['resource'] for f in response['findings']}=={'one','two'}

@mock_aws
def test_all_region_scanner_bounds_and_closes_clients(monkeypatch):
    from src.tools import Inputs, result
    from unittest.mock import Mock
    auditor=Auditor(boto3.Session(region_name='us-east-1'))
    ec2=Mock()
    ec2.describe_regions.return_value={'Regions':[{'RegionName':f'us-test-{i}'} for i in range(8)]}
    monkeypatch.setattr(auditor,'client',lambda name:ec2)
    lock=threading.Lock()
    active=peak=closed=0
    class Client:
        def __init__(self):
            nonlocal active,peak
            with lock:
                active+=1
                peak=max(peak,active)
        def close(self):
            nonlocal active,closed
            with lock:
                active-=1
                closed+=1
    def call(self,name,**kwargs):
        if self is not auditor and not self.clients:
            self.clients['test']=Client()
        data={'services':[]} if name=='get_cost_breakdown' else {'Total':{'Amount':'0'}} if name=='get_cost_forecast' else {'anomalies':[]} if name=='find_cost_anomalies' else {}
        return result(name,data)
    monkeypatch.setattr(Auditor,'call',call)
    report=auditor.all_region_report(Inputs())
    assert report['coverage']=='complete'
    assert len(report['data']['regions'])==8
    assert peak<=3 and active==0 and closed==8
