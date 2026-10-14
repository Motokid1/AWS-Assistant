"""Deterministic two-stage demo using the production scoring formula."""
from .models import result, WEIGHTS
_STAGE = 0
JOB_ID = '00000000-0000-4000-8000-000000000001'

def report(stage=None):
    from .tools import finding
    stage = _STAGE if stage is None else stage
    findings = [finding('security','CRITICAL','demo-assets','Public S3 bucket','Enable S3 Block Public Access after reviewing access requirements.'), finding('security','HIGH','demo-engineer','Console user without MFA','Enroll an authenticator.'), finding('security','HIGH','sg-demo','Internet-exposed SSH','Restrict ingress or use Systems Manager.'), finding('waste','MEDIUM','vol-demo','Unattached EBS volume','Confirm ownership and backup requirements before manual deletion.',40), finding('observability','MEDIUM','checkout-errors','Checkout error alarm','Investigate application errors.')]
    if stage: findings = [f for f in findings if f['category']=='observability']
    score=max(0,100-sum(WEIGHTS[f['severity']] for f in findings))
    tools = {'get_cost_breakdown':result('Demo costs',{'services':[{'service':'EC2','amount':620},{'service':'NAT Gateway','amount':380},{'service':'RDS','amount':280},{'service':'S3','amount':92},{'service':'Lambda','amount':48}]}), 'get_cost_forecast':result('Demo forecast',{'Total':{'Amount':'1720','Unit':'USD'}}), 'find_cost_anomalies':result('Demo anomaly',{'anomalies':[{'service':'NAT Gateway','impact':180,'description':'Illustrative contributor, not proof of misconfiguration.'}]}), 'get_free_tier_usage':result('Demo usage',{'usage':[{'service':'AWS Lambda','actualUsageAmount':120000,'limit':1000000,'unit':'Requests'}]}), 'list_active_alarms':result('Demo alarm',{'alarms':[{'AlarmName':'checkout-errors','StateValue':'ALARM','StateReason':'Error threshold exceeded'}]})}
    r=result('Illustrative before/after demo. No AWS resources were queried or changed.',{'health_score':score,'coverage':'demo','region':'demo','regions':['demo'],'scope':'demo','estimated_monthly_savings':sum(f['estimated_monthly_savings'] for f in findings),'tools':tools},findings)
    r['observed_at']='2026-10-07T04:00:00+00:00' if not stage else '2026-10-07T04:05:00+00:00'
    return r

def rescan():
    global _STAGE
    _STAGE=1
    return {'job_id':JOB_ID,'status':'COMPLETED','coverage':'demo','summary':'Simulated manual fixes followed by a rescan; no AWS changes occurred.'}

def reset():
    global _STAGE
    _STAGE=0

def history(): return [report(0),report(1)] if _STAGE else [report(0)]

def tool(name,params):
    r=report()
    if name=='generate_account_health_report': return r
    if name in r['data']['tools']: return r['data']['tools'][name]
    if name=='get_lambda_logs': return result('Demo logs',{'events':[{'timestamp':1791345600000,'message':'ERROR checkout payment provider timeout'}],'untrusted_data':True})
    if name=='get_lambda_metrics': return result('Demo metrics',{'Invocations':[{'Timestamp':'2026-10-07T04:00:00Z','Sum':100}],'Errors':[{'Timestamp':'2026-10-07T04:00:00Z','Sum':3}],'Duration':[{'Timestamp':'2026-10-07T04:00:00Z','Average':120}]})
    if name=='explain_aws_service': return result('Illustrative demo explanation; Bedrock was not called.',{'explanation':params.get('service_name','EC2')+' should be reviewed for unused capacity, public access and least privilege. This is a deterministic demo response. Live mode uses Amazon Bedrock Converse.','model':'demo'})
    categories={'find_public_buckets':'Public S3','audit_iam_users':'Console user','check_open_security_groups':'Internet-exposed','find_unused_ebs_volumes':'Unattached','find_unused_elastic_ips':'Unused','find_old_snapshots':'Old snapshot'}
    return result('Demo: '+name,{},[f for f in r['findings'] if f['title'].startswith(categories.get(name,'__none__'))])
