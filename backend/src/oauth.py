"""OAuth authorization-code + PKCE bridge to the deployment's Cognito login.
Opaque tokens are hashed at rest, bound to one MCP resource, and expire after 15 minutes.
"""
import base64, hashlib, hmac, html, json, os, re, secrets, time
from urllib.parse import urlencode, urlparse, parse_qs
import boto3, httpx, jwt
from botocore.exceptions import ClientError
from starlette.responses import JSONResponse, RedirectResponse, HTMLResponse
from .storage import table


def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def challenge(value): return base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip('=')
def issuer(request):
    host=request.scope.get('aws.event',{}).get('requestContext',{}).get('domainName')
    return 'https://'+host if host else str(request.base_url).rstrip('/')
def put(key,value,ttl): table().put_item(Item={'pk':key,**value,'ttl':int(time.time())+ttl})
def get(key):
    row=table().get_item(Key={'pk':key},ConsistentRead=True).get('Item')
    return row if row and row.get('ttl',0)>time.time() else None

def consume(key):
    try:
        response=table().delete_item(Key={'pk':key},ConditionExpression='#ttl > :now',ExpressionAttributeNames={'#ttl':'ttl'},ExpressionAttributeValues={':now':int(time.time())},ReturnValues='ALL_OLD')
        return response.get('Attributes')
    except ClientError as e:
        if e.response['Error']['Code']=='ConditionalCheckFailedException': return None
        raise

def valid_redirect(url):
    p=urlparse(url)
    return not p.fragment and not p.username and not p.password and (p.scheme=='https' and bool(p.hostname) or p.scheme=='http' and p.hostname in ('localhost','127.0.0.1','::1'))

async def resource_metadata(request):
    base=issuer(request)
    return JSONResponse({'resource':base+'/mcp','authorization_servers':[base],'scopes_supported':['audit:read'],'bearer_methods_supported':['header']})
async def server_metadata(request):
    base=issuer(request)
    return JSONResponse({'issuer':base,'authorization_endpoint':base+'/oauth/authorize','token_endpoint':base+'/oauth/token','registration_endpoint':base+'/oauth/register','response_types_supported':['code'],'grant_types_supported':['authorization_code'],'token_endpoint_auth_methods_supported':['none'],'code_challenge_methods_supported':['S256'],'scopes_supported':['audit:read']})
async def register(request):
    data=await request.json(); redirects=data.get('redirect_uris',[])
    if not 1<=len(redirects)<=5 or not all(isinstance(u,str) and len(u)<=2048 and valid_redirect(u) for u in redirects): return JSONResponse({'error':'invalid_redirect_uri'},status_code=400)
    if data.get('token_endpoint_auth_method','none')!='none': return JSONResponse({'error':'invalid_client_metadata'},status_code=400)
    cid=secrets.token_urlsafe(24)
    value={'client_id':cid,'redirect_uris':redirects,'client_name':str(data.get('client_name','MCP client'))[:80],'grant_types':['authorization_code'],'response_types':['code'],'token_endpoint_auth_method':'none'}
    put('oauth#client#'+cid,value,90*86400)
    return JSONResponse(value,status_code=201)
async def authorize(request):
    q=request.query_params; client=get('oauth#client#'+q.get('client_id','')); base=issuer(request)
    if not client or q.get('redirect_uri') not in client['redirect_uris'] or q.get('response_type')!='code' or q.get('code_challenge_method')!='S256' or not re.fullmatch(r'[A-Za-z0-9_-]{43}',q.get('code_challenge','')): return JSONResponse({'error':'invalid_request'},status_code=400)
    if q.get('resource')!=base+'/mcp' or q.get('scope','audit:read')!='audit:read': return JSONResponse({'error':'invalid_target'},status_code=400)
    flow=secrets.token_urlsafe(32)
    put('oauth#flow#'+digest(flow),{'client_id':q['client_id'],'redirect_uri':q['redirect_uri'],'challenge':q['code_challenge'],'state':q.get('state',''),'resource':base+'/mcp'},600)
    page=f'''<!doctype html><html><body><h1>Connect {html.escape(client['client_name'])}</h1><p>Allow this client to read AWS account audit results, resource names, costs and Lambda logs through AWS Assistant? It cannot modify audited resources.</p><form method="post" action="/oauth/consent"><input type="hidden" name="flow" value="{flow}"><button type="submit">Continue to secure sign-in</button></form><p>Close this page to decline.</p></body></html>'''
    response=HTMLResponse(page,headers={'Content-Security-Policy':"default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",'Cache-Control':'no-store'})
    response.set_cookie('oauth-flow',flow,max_age=600,secure=base.startswith('https'),httponly=True,samesite='lax')
    return response
async def consent(request):
    data=parse_qs((await request.body()).decode()); flow=data.get('flow',[''])[0]
    if not flow or not hmac.compare_digest(flow,request.cookies.get('oauth-flow','')): return JSONResponse({'error':'invalid_request'},status_code=400)
    record=consume('oauth#flow#'+digest(flow))
    if not record:return JSONResponse({'error':'expired_flow'},status_code=400)
    upstream=secrets.token_urlsafe(32); verifier=secrets.token_urlsafe(48)
    put('oauth#state#'+digest(upstream),{**record,'verifier':verifier},600)
    args={'client_id':os.environ['OAUTH_LOGIN_CLIENT'],'response_type':'code','scope':'openid email profile','redirect_uri':issuer(request)+'/oauth/callback','state':upstream,'code_challenge_method':'S256','code_challenge':challenge(verifier)}
    return RedirectResponse(os.environ['COGNITO_DOMAIN']+'/oauth2/authorize?'+urlencode(args),status_code=303)
async def callback(request):
    record=consume('oauth#state#'+digest(request.query_params.get('state','')))
    if not record:return JSONResponse({'error':'invalid_state'},status_code=400)
    if not request.query_params.get('code'):return JSONResponse({'error':'authorization_denied'},status_code=400)
    async with httpx.AsyncClient(timeout=10) as client:
        response=await client.post(os.environ['COGNITO_DOMAIN']+'/oauth2/token',data={'grant_type':'authorization_code','client_id':os.environ['OAUTH_LOGIN_CLIENT'],'code':request.query_params['code'],'redirect_uri':issuer(request)+'/oauth/callback','code_verifier':record['verifier']})
    if response.status_code!=200:return JSONResponse({'error':'upstream_authorization_failed'},status_code=400)
    token=response.json()['id_token']
    def verify():
        origin=os.environ['COGNITO_ISSUER']; key=jwt.PyJWKClient(origin+'/.well-known/jwks.json').get_signing_key_from_jwt(token).key
        return jwt.decode(token,key,algorithms=['RS256'],audience=os.environ['OAUTH_LOGIN_CLIENT'],issuer=origin,options={'require':['exp','sub','iss','aud']})
    import asyncio
    claims=await asyncio.to_thread(verify)
    code=secrets.token_urlsafe(32)
    put('oauth#code#'+digest(code),{k:record[k] for k in ('client_id','redirect_uri','challenge','resource')}|{'sub':claims['sub']},120)
    url=record['redirect_uri']+('?' if '?' not in record['redirect_uri'] else '&')+urlencode({'code':code,'state':record['state']})
    return RedirectResponse(url,status_code=303)
async def exchange(request):
    values={k:v[0] for k,v in parse_qs((await request.body()).decode()).items()}
    if values.get('grant_type')!='authorization_code': return JSONResponse({'error':'unsupported_grant_type'},status_code=400)
    key='oauth#code#'+digest(values.get('code','')); record=get(key)
    verifier=values.get('code_verifier','')
    if not record or not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}',verifier) or not hmac.compare_digest(challenge(verifier),record['challenge']) or any(values.get(k)!=record[k] for k in ('client_id','redirect_uri','resource')): return JSONResponse({'error':'invalid_grant'},status_code=400)
    # Atomic consume prevents replay, including concurrent exchanges.
    record=consume(key)
    if not record:return JSONResponse({'error':'invalid_grant'},status_code=400)
    access=secrets.token_urlsafe(48)
    put('oauth#token#'+digest(access),{'sub':record['sub'],'resource':record['resource'],'client_id':record['client_id'],'scope':'audit:read'},900)
    return JSONResponse({'access_token':access,'token_type':'Bearer','expires_in':900,'scope':'audit:read'},headers={'Cache-Control':'no-store','Pragma':'no-cache'})
def verify_token(token,resource):
    record=get('oauth#token#'+digest(token))
    return bool(record and record['resource']==resource and record['scope']=='audit:read')
