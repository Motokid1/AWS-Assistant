"""Explicitly registered read-only cross-account connections."""
import json, os, re, secrets, uuid
import boto3
from pydantic import BaseModel, Field

class Connection(BaseModel):
    name: str = Field(min_length=1,max_length=80)
    role_arn: str = Field(pattern=r'^arn:aws(?:-us-gov|-cn)?:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+$')

def connection_table(): return boto3.resource('dynamodb').Table(os.environ['SCAN_TABLE'])
def connections():
    if os.getenv('DEMO_MODE')=='true': return []
    from boto3.dynamodb.conditions import Key
    rows=[];args={'IndexName':'kind-index','KeyConditionExpression':Key('kind').eq('connection')}
    while True:
        response=connection_table().query(**args);rows.extend(response.get('Items',[]))
        if not response.get('LastEvaluatedKey'):break
        args['ExclusiveStartKey']=response['LastEvaluatedKey']
    return [{'id':r['id'],'name':r['name'],'role_arn':r['role_arn']} for r in rows]
def create_connection(body):
    spec=Connection.model_validate(body)
    allowed=os.getenv('ALLOWED_ROLE_ARNS','').split(',')
    if spec.role_arn not in allowed: raise ValueError('Role ARN is not in the deployment allowlist')
    cid=str(uuid.uuid4()); external=secrets.token_urlsafe(32)
    connection_table().put_item(Item={'pk':'connection#'+cid,'kind':'connection','sort':cid,'id':cid,**spec.model_dump(),'external_id':external})
    return {'id':cid,**spec.model_dump(),'external_id':external,'instructions':'Use this External ID in the customer role trust policy. The audit role must be read-only.'}
def session_for(connection_id='',region=None):
    if not connection_id: return boto3.Session(region_name=region or os.getenv('AWS_REGION','us-east-1'))
    if not re.fullmatch(r'[0-9a-f-]{36}',connection_id): raise ValueError('Invalid connection ID')
    row=connection_table().get_item(Key={'pk':'connection#'+connection_id},ConsistentRead=True).get('Item')
    if not row: raise ValueError('Unknown connection')
    # No role ARN or External ID comes from an untrusted tool argument.
    creds=boto3.client('sts').assume_role(RoleArn=row['role_arn'],RoleSessionName='aws-assistant-audit',ExternalId=row['external_id'],DurationSeconds=900)['Credentials']
    return boto3.Session(aws_access_key_id=creds['AccessKeyId'],aws_secret_access_key=creds['SecretAccessKey'],aws_session_token=creds['SessionToken'],region_name=region or os.getenv('AWS_REGION','us-east-1'))
