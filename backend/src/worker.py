"""IAM-authenticated Lambda worker used by the credential-free dashboard API."""
from pydantic import BaseModel, Field
from .storage import cached_call, run_audit

READ_TOOLS={'list_active_alarms','get_free_tier_usage','get_lambda_logs','get_lambda_metrics','explain_aws_service'}
class Request(BaseModel):
    tool: str
    params: dict = Field(default_factory=dict)
    connection_id: str = Field(default='',max_length=36)
    region: str = Field(default='',max_length=32)

def handler(event,context):
    request=Request.model_validate(event)
    if request.tool not in READ_TOOLS: raise ValueError('Tool is not available through dashboard RPC')
    return cached_call(request.tool,connection_id=request.connection_id,region=request.region,**request.params)
