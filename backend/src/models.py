"""Validated response contracts and byte-bounded serialization."""
import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Literal
from pydantic import BaseModel, Field

RESPONSE_BYTES = 500_000
WEIGHTS = {'CRITICAL': 20, 'HIGH': 8, 'MEDIUM': 2, 'LOW': 1}

class Finding(BaseModel):
    id: str
    category: str
    severity: Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    resource: str
    title: str
    suggested_fix: str
    estimated_monthly_savings: float = 0

class ToolResult(BaseModel):
    summary: str = Field(min_length=1, max_length=4096)
    findings: list[Finding] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    errors: list[dict[str, Any]] = Field(default_factory=list)
    observed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    truncated: bool = False

class AccountReport(ToolResult):
    score: int | None = Field(ge=0, le=100)
    coverage: Literal['complete', 'partial', 'demo', 'pending']


def serialized_size(value):
    return len(json.dumps(value, default=lambda x: float(x) if isinstance(x, Decimal) else x.isoformat(), ensure_ascii=True).encode('utf-8'))


def bounded_response(value, max_bytes=RESPONSE_BYTES):
    """Re-measure after every stage. Report identity and metadata always survive."""
    report = 'score' in value or 'health_score' in value.get('data', {})
    if report:
        value.setdefault('score', value['data'].get('health_score'))
        value.setdefault('coverage', value['data'].get('coverage', 'partial'))
    model = AccountReport if report else ToolResult
    payload = model.model_validate(value).model_dump(mode='json')
    cut = payload['truncated']

    def shorten(v, chars=4096):
        nonlocal cut
        if isinstance(v, str):
            if len(v) > chars: cut = True
            return v[:chars]
        if isinstance(v, list):
            if len(v) > 200: cut = True
            return [shorten(x, chars) for x in v[:200]]
        if isinstance(v, dict):
            if len(v) > 200: cut = True
            return {str(k)[:chars]: shorten(x, chars) for k, x in list(v.items())[:200]}
        return v

    payload['data'] = shorten(payload['data'])
    payload['findings'] = shorten(payload['findings'])
    payload['errors'] = shorten(payload['errors'])

    def mark():
        payload['truncated'] = True
        if report:
            payload['score'] = None
            payload['coverage'] = 'partial'
            payload['data']['health_score'] = None
            payload['data']['coverage'] = 'partial'

    if cut: mark()
    if serialized_size(payload) > max_bytes:
        # Scalar report metadata is protected; only the optional raw data is dropped.
        keep = ('health_score', 'coverage', 'region', 'estimated_monthly_savings') if report else ()
        payload['data'] = {k: payload['data'][k] for k in keep if k in payload['data']}
        mark()
    while serialized_size(payload) > max_bytes and payload['findings']:
        payload['findings'] = payload['findings'][:len(payload['findings']) // 2]
        mark()
    chars = 2048
    while serialized_size(payload) > max_bytes and chars >= 16:
        payload['findings'] = shorten(payload['findings'], chars)
        payload['errors'] = shorten(payload['errors'], chars)
        mark()
        chars //= 2
    while serialized_size(payload) > max_bytes and payload['errors']:
        payload['errors'] = payload['errors'][:len(payload['errors']) // 2]
        mark()
    if serialized_size(payload) > max_bytes:
        raise ValueError('Response byte budget too small for required report fields')
    return model.model_validate(payload).model_dump(mode='json')


def result(summary, data=None, findings=None, truncated=False, errors=None):
    return bounded_response(dict(summary=summary, data=data or {}, findings=findings or [], errors=errors or [], truncated=truncated))
