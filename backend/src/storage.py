"""Stored reports, bounded caches, and deduplicated scan jobs."""
import os, json, time, uuid, logging
from decimal import Decimal
import boto3
from boto3.dynamodb.types import TypeSerializer
from botocore.exceptions import ClientError
from .tools import Auditor, Inputs, demo_report
from .models import bounded_response, result

log = logging.getLogger(__name__)
COST_TOOLS = {'get_cost_breakdown', 'get_cost_forecast', 'find_cost_anomalies'}
CACHE_ITEM_BYTES = 300_000
SCAN_LEASE_SECONDS = 960


def plain(value):
    return json.loads(json.dumps(value, default=lambda x: float(x) if isinstance(x, Decimal) else x.isoformat()))


def encoded(value):
    return json.loads(json.dumps(plain(value)), parse_float=Decimal)


def table():
    return boto3.resource('dynamodb').Table(os.environ['SCAN_TABLE'])


def item_size(item):
    # Include DynamoDB type wrappers and all item attributes; conservative overestimate.
    return len(json.dumps(TypeSerializer().serialize(encoded(item)), ensure_ascii=True).encode('utf-8'))


def latest(connection_id=''):
    if os.getenv('DEMO_MODE') == 'true': return demo_report()
    row = table().get_item(Key={'pk': 'latest'+('#'+connection_id if connection_id else '')}, ConsistentRead=True).get('Item', {})
    return plain(row.get('report'))


def cache_epoch():
    row = table().get_item(Key={'pk': 'cache#epoch'}, ConsistentRead=True).get('Item', {})
    return str(row.get('generation', 'initial'))


def cache_key(name, params, generation):
    return 'cache:' + generation + ':' + name + ':' + json.dumps(params, sort_keys=True)


def write_cache(key, name, report):
    item = {'pk': key, 'ttl': int(time.time()) + (3600 if name in COST_TOOLS else 900), 'report': encoded(report)}
    size = item_size(item)
    if size > CACHE_ITEM_BYTES:
        log.warning('cache_skipped_oversize tool=%s bytes=%s', name, size)
        return False
    try:
        table().put_item(Item=item)
        return True
    except ClientError:
        log.warning('cache_write_failed tool=%s', name, exc_info=True)
        return False


def cached_call(name, refresh=False, live=False, connection_id='', region='', **params):
    log.info('tool_call %s', name)
    normalized = Inputs(**params).model_dump()
    if name == 'generate_account_health_report' and not live:
        stored = latest(connection_id) if os.getenv('SCAN_TABLE') or os.getenv('DEMO_MODE') == 'true' else None
        return stored or result('No stored scan is available. Request a scan or use live=true.', {'health_score': None, 'coverage': 'pending', 'region': os.getenv('AWS_REGION', 'us-east-1')}, errors=[{'tool': name, 'code': 'NoStoredReport'}])
    if name == 'generate_account_health_report' and live: refresh = True
    if not os.getenv('SCAN_TABLE') or os.getenv('DEMO_MODE') == 'true':
        return run_audit(name,normalized,connection_id,region)
    generation = cache_epoch() + ':' + connection_id + ':' + region
    key = cache_key(name, normalized, generation)
    if not refresh:
        row = table().get_item(Key={'pk': key}, ConsistentRead=True).get('Item')
        if row and row['ttl'] > time.time(): return plain(row['report'])
    report = run_audit(name,normalized,connection_id,region)
    if not report['errors']: write_cache(key, name, report)
    return report


def reserve_scan(connection_id=''):
    now = int(time.time())
    job = {'job_id': str(uuid.uuid4()), 'status': 'QUEUED', 'connection_id':connection_id, 'requested_at': now, 'lease_until': now + SCAN_LEASE_SECONDS}
    try:
        table().put_item(Item={'pk': 'scan#status', **job}, ConditionExpression='attribute_not_exists(pk) OR (#s <> :queued AND #s <> :running) OR lease_until < :now', ExpressionAttributeNames={'#s': 'status'}, ExpressionAttributeValues={':queued': 'QUEUED', ':running': 'RUNNING', ':now': now})
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ConditionalCheckFailedException': raise
        current = table().get_item(Key={'pk': 'scan#status'}, ConsistentRead=True)['Item']
        return plain({k: v for k, v in current.items() if k != 'pk'}), False
    try:
        table().put_item(Item={'pk': 'scan#' + job['job_id'], **job, 'ttl': now + 90 * 86400})
    except Exception:
        table().update_item(Key={'pk': 'scan#status'}, UpdateExpression='SET #s = :failed', ConditionExpression='job_id = :job', ExpressionAttributeNames={'#s': 'status'}, ExpressionAttributeValues={':failed': 'FAILED', ':job': job['job_id']})
        raise
    return job, True


def scan_status(job_id):
    if os.getenv('DEMO_MODE')=='true':
        from .demo import JOB_ID
        return {'job_id':JOB_ID,'status':'COMPLETED','coverage':'demo'} if job_id==JOB_ID else None
    if not job_id or len(job_id) != 36:
        return None
    row = table().get_item(Key={'pk': 'scan#' + job_id}, ConsistentRead=True).get('Item')
    if not row: return None
    job = plain({k: v for k, v in row.items() if k not in ('pk', 'ttl')})
    if job['status'] in ('QUEUED', 'RUNNING') and job['lease_until'] < time.time():
        job['status'] = 'FAILED'; job['error'] = 'Scan lease expired; request a new scan.'
    return job


def finish_job(job_id, status, **details):
    updates = {'status': status, 'finished_at': int(time.time()), **details}
    names = {'#' + k: k for k in updates}
    values = {':' + k: encoded(v) for k, v in updates.items()}
    expression = 'SET ' + ', '.join('#' + k + ' = :' + k for k in updates)
    table().update_item(Key={'pk': 'scan#' + job_id}, UpdateExpression=expression, ExpressionAttributeNames=names, ExpressionAttributeValues=values)
    try:
        table().update_item(Key={'pk': 'scan#status'}, UpdateExpression=expression, ConditionExpression='job_id = :job', ExpressionAttributeNames=names, ExpressionAttributeValues={**values, ':job': job_id})
    except ClientError as exc:
        if exc.response['Error']['Code'] != 'ConditionalCheckFailedException': raise


def request_scan(connection_id=''):
    if os.getenv('DEMO_MODE') == 'true':
        from .demo import rescan
        return rescan()
    if connection_id:
        if not table().get_item(Key={'pk':'connection#'+connection_id},ConsistentRead=True).get('Item'): raise ValueError('Unknown account connection')
    job, created = reserve_scan(connection_id)
    if job.get('connection_id','')!=connection_id: raise ValueError('A scan for another account is already active.')
    if created:
        try:
            boto3.client('lambda').invoke(FunctionName=os.environ['SCAN_FUNCTION'], InvocationType='Event', Payload=json.dumps({'job_id': job['job_id']}).encode())
        except Exception:
            finish_job(job['job_id'], 'FAILED', error='Unable to queue scan.')
            raise
    return {**job, 'deduplicated': not created}


def fit_snapshot(report):
    # Preserve schema and verify the whole DynamoDB item, not just report JSON.
    for budget in (250_000, 200_000, 100_000, 50_000):
        fitted = bounded_response(report, max_bytes=budget)
        if item_size({'pk': 'latest', 'report': fitted}) <= CACHE_ITEM_BYTES: return fitted
    raise ValueError('Unable to fit validated scan snapshot')


def scan_one(event, context):
    job_id = event.get('job_id')
    if not job_id:
        job, created = reserve_scan(event.get('connection_id',''))
        if not created: return {**job, 'deduplicated': True}
        job_id = job['job_id']
    try:
        table().update_item(Key={'pk': 'scan#status'}, UpdateExpression='SET #s = :running', ConditionExpression='job_id = :job AND #s = :queued AND lease_until >= :now', ExpressionAttributeNames={'#s': 'status'}, ExpressionAttributeValues={':running': 'RUNNING', ':queued': 'QUEUED', ':job': job_id, ':now': int(time.time())})
    except ClientError as exc:
        if exc.response['Error']['Code'] == 'ConditionalCheckFailedException': return {'job_id': job_id, 'status': 'IGNORED'}
        raise
    try:
        table().update_item(Key={'pk': 'scan#' + job_id}, UpdateExpression='SET #s = :running', ExpressionAttributeNames={'#s': 'status'}, ExpressionAttributeValues={':running': 'RUNNING'})
        # Direct Auditor calls bypass all MCP caches; checks execute concurrently.
        lock=table().get_item(Key={'pk':'scan#status'},ConsistentRead=True)['Item']
        connection_id=lock.get('connection_id','')
        report = plain(run_audit('generate_account_health_report',{'days':30,'limit':100,'older_than_days':90},connection_id))
        report['data']['tools'] = {k: {'summary': v['summary'], 'data': v['data'] if k in COST_TOOLS else {}, 'errors': v['errors'], 'truncated': v['truncated']} for k, v in report['data'].get('tools', {}).items()}
        snapshot = fit_snapshot(report)
        # A transaction publishes the snapshot and invalidates every old tool-cache variant.
        table().meta.client.transact_write_items(TransactItems=[
            {'ConditionCheck': {'TableName': table().name, 'Key': {'pk': 'scan#status'}, 'ConditionExpression': 'job_id = :job AND #s = :running', 'ExpressionAttributeNames': {'#s': 'status'}, 'ExpressionAttributeValues': {':job': job_id, ':running': 'RUNNING'}}},
            {'Put': {'TableName': table().name, 'Item': {'pk': 'latest'+('#'+connection_id if connection_id else ''), 'report': encoded(snapshot)}}},
            {'Put': {'TableName': table().name, 'Item': {'pk': 'cache#epoch', 'generation': job_id}}},
        ])
        history = dict(snapshot); history['data'] = dict(snapshot['data']); history['data']['tools'] = {}
        table().put_item(Item={'pk': 'history:' + job_id, 'kind':'history'+('#'+connection_id if connection_id else ''),'sort':snapshot['observed_at'],'ttl': int(time.time()) + 90 * 86400, 'report': encoded(history)})
        finish_job(job_id, 'COMPLETED', coverage=snapshot['coverage'], observed_at=snapshot['observed_at'])
        if os.getenv('REPORT_TOPIC'):
            try:
                boto3.client('sns').publish(TopicArn=os.environ['REPORT_TOPIC'],Subject='AWS Assistant account scan',Message=json.dumps({'score':snapshot['score'],'coverage':snapshot['coverage'],'findings':len(snapshot['findings']),'estimated_savings':snapshot['data'].get('estimated_monthly_savings'),'observed_at':snapshot['observed_at']}))
            except Exception:
                log.exception('report_notification_failed job_id=%s',job_id)
        return {'job_id': job_id, 'status': 'COMPLETED', 'coverage': snapshot['coverage']}
    except Exception:
        log.exception('scan_failed job_id=%s', job_id)
        finish_job(job_id, 'FAILED', error='Scan failed; inspect scanner logs.')
        raise



def run_audit(name, params, connection_id='', region=''):
    if region:
        import re
        if not re.fullmatch(r'[a-z0-9-]{5,32}',region): raise ValueError('Invalid region')
    if not connection_id and not region: return Auditor().call(name,**params)
    from .connections import session_for
    return Auditor(session_for(connection_id,region or None)).call(name,**params)


def report_history(limit=30,connection_id=''):
    if not 1<=limit<=90: raise ValueError('History limit must be 1–90')
    if os.getenv('DEMO_MODE')=='true':
        from .demo import history
        return history()[-limit:]
    from boto3.dynamodb.conditions import Key
    rows=[];args={'IndexName':'kind-index','KeyConditionExpression':Key('kind').eq('history'+('#'+connection_id if connection_id else '')),'ScanIndexForward':False,'Limit':limit}
    while len(rows)<limit:
        response=table().query(**args);rows.extend(response.get('Items',[]))
        if not response.get('LastEvaluatedKey') or len(rows)>=limit:break
        args['ExclusiveStartKey']=response['LastEvaluatedKey'];args['Limit']=limit-len(rows)
    return list(reversed([plain(r['report']) for r in rows]))


def scan_handler(event,context):
    if event.get('job_id') or event.get('connection_id') or os.getenv('SCAN_MULTI_ACCOUNT')!='true':
        return scan_one(event,context)
    from .connections import connections
    return [scan_one({'connection_id':cid},context) for cid in ['']+[c['id'] for c in connections()]]
