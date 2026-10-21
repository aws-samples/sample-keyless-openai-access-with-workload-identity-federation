# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""IAM -> OpenAI translator, per PERSON: one OpenAI-compatible endpoint (Lambda Function URL, AWS_IAM).

The AgentCore Gateway's one inference target (`openai`) points here (/v1/...); Cedar has already checked the
person's group may use the requested model. The Gateway signs with SigV4 (its IAM role) and forwards the caller's
delegated Okta token in X-Person-Token (header propagation). Per person this function:
  1. hands that Okta token to STS: AssumeRoleWithWebIdentity (IAM OIDC provider = Okta wif-gateway). The token is
     the credential; this function needs no AWS permission for it. IAM is the mapping: the team role's trust
     admits the token only if its team tag (from the Okta group) is that role's team.
  2. the session carries the person: source identity = their login, session tags team + user,
  3. mints an AWS-signed JWT as that session: sub = team role, source_identity + principal_tags.user = the person,
  4. exchanges it at OpenAI for a short-lived token (the team's service account) and forwards the call.
No key is stored anywhere; everything lives in memory until shortly before it expires.
"""
import base64
import hashlib
import json
import os
import time
import urllib.error
import urllib.request

import boto3
from botocore import UNSIGNED
from botocore.config import Config

# HTTPS only: urllib.request.urlopen would also open file:// and other schemes
_HTTPS = urllib.request.OpenerDirector()
for _h in (urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPRedirectHandler(),
           urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(), urllib.request.UnknownHandler()):
    _HTTPS.add_handler(_h)

REGION = os.environ.get("AWS_REGION", "us-east-1")
PROVIDER_ID = os.environ["OPENAI_IDENTITY_PROVIDER_ID"]
TEAM_ROLES = json.loads(os.environ["TEAM_ROLES"])               # {"engineering": "arn:...:role/...", ...}
SERVICE_ACCOUNTS = json.loads(os.environ["SERVICE_ACCOUNTS"])   # {"engineering": "user-...", ...}
MODELS = json.loads(os.environ.get("MODELS", "[]"))              # what the Gateway target lists (answered locally)
STS_URL = f"https://sts.{REGION}.amazonaws.com"
JWT_SECONDS = 900
TAG = "https://aws.amazon.com/tags/principal_tags/"
sts_anon = boto3.client("sts", region_name=REGION, endpoint_url=STS_URL, config=Config(signature_version=UNSIGNED))   # the token is the credential
_people = {}   # sha256(okta token) -> {"user_id", "team", "creds", "exp", "token", "token_exp"}


def claims(tok):
    p = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def header(tok):
    h = tok.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))


def session_name(login):
    return ("person-" + "".join(ch if ch.isalnum() or ch in "+=,.@-_" else "-" for ch in login))[:64]


def person(okta_token):
    key = hashlib.sha256(okta_token.encode()).hexdigest()
    p = _people.get(key)
    if p and time.time() < p["exp"] - (JWT_SECONDS + 60):
        return p
    c = claims(okta_token)
    team = c.get(TAG + "team")                                   # Okta's group -> team; IAM checks it fits the role
    if team not in TEAM_ROLES:
        raise PermissionError("the token carries no known team tag")
    r = sts_anon.assume_role_with_web_identity(RoleArn=TEAM_ROLES[team], RoleSessionName=session_name(c.get("sub", "")),
                                               WebIdentityToken=okta_token, DurationSeconds=3600)
    cr = r["Credentials"]
    p = _people[key] = {"user_id": r.get("SourceIdentity") or c.get("sub"), "team": team, "creds": cr, "exp": cr["Expiration"].timestamp()}
    print(json.dumps({"event": "web_identity", "team": team, "person": p["user_id"], "role": TEAM_ROLES[team], "session": r["AssumedRoleUser"]["Arn"],
                      "source_identity": r.get("SourceIdentity"), "subject": r.get("SubjectFromWebIdentityToken"), "provider": r.get("Provider"),
                      "audience": r.get("Audience"), "session_tags": {k[len(TAG):]: v for k, v in c.items() if k.startswith(TAG)},
                      "expires": cr["Expiration"].isoformat()}))
    return p


def openai_token(p):
    if p.get("token") and time.time() < p["token_exp"] - 60:
        return p["token"]
    c = p["creds"]
    s = boto3.client("sts", region_name=REGION, endpoint_url=STS_URL, aws_access_key_id=c["AccessKeyId"],
                     aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"])
    jwt = s.get_web_identity_token(Audience=["https://api.openai.com/v1"], SigningAlgorithm="ES384", DurationSeconds=JWT_SECONDS)["WebIdentityToken"]
    c = claims(jwt)
    ns = c.get("https://sts.amazonaws.com/", {})
    # evidence, no secrets: what the AWS token sent to OpenAI says about who it is for
    print(json.dumps({"event": "aws_jwt_minted", "team": p["team"], "person": p["user_id"], "sub": c.get("sub"), "aud": c.get("aud"),
                      "source_identity": ns.get("source_identity"), "jti": c.get("jti"), "iat": c.get("iat"), "exp": c.get("exp"),
                      "service_account_id": SERVICE_ACCOUNTS[p["team"]], "claims": c, "header": header(jwt)}))
    body = json.dumps({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                       "subject_token": jwt, "identity_provider_id": PROVIDER_ID, "service_account_id": SERVICE_ACCOUNTS[p["team"]]}).encode()
    req = urllib.request.Request("https://auth.openai.com/oauth/token", data=body, headers={"Content-Type": "application/json", "User-Agent": "openai-wif-translator/3.0"})
    with _HTTPS.open(req, timeout=15) as r:
        resp = json.loads(r.read())
    p.update(token=resp["access_token"], token_exp=time.time() + resp["expires_in"], aws_jti=c.get("jti"))
    oc = claims(resp["access_token"])
    p["openai_jti"] = oc.get("jti")
    print(json.dumps({"event": "openai_token_issued", "team": p["team"], "person": p["user_id"], "jti": oc.get("jti"), "aws_jwt_jti": c.get("jti"),
                      "token_type": resp.get("token_type"), "expires_in": resp.get("expires_in"), "claims": oc, "header": header(resp["access_token"])}))
    return p["token"]


def reply(status, message):
    return {"statusCode": status, "headers": {"Content-Type": "application/json"}, "body": json.dumps({"error": {"message": message, "type": "permission_error"}})}


def handler(event, _ctx):
    method, path = event["requestContext"]["http"]["method"], event.get("rawPath", "/")
    first, _, rest = path.lstrip("/").partition("/")
    if first in TEAM_ROLES:            # legacy per-team target path
        team = first
    elif first == "v1":                # the one target: the team comes from the person
        team, rest = None, path.lstrip("/")
    else:
        return reply(404, f"unknown path '{path}'")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    person_token = headers.get("x-person-token", "")
    body = event.get("body")
    body = base64.b64decode(body) if body and event.get("isBase64Encoded") else (body.encode() if body else None)
    if not person_token:
        if method == "GET" and rest.startswith("v1/models"):
            # model discovery by the Gateway itself (no person): answer with the configured models; no role, no OpenAI call
            print(json.dumps({"event": "call", "person": "gateway-discovery", "method": method, "path": "/" + rest, "models": MODELS}))
            return {"statusCode": 200, "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({"object": "list", "data": [{"id": m, "object": "model", "owned_by": "openai"} for m in MODELS]})}
        else:
            return reply(401, "no person token: calls must come through the Gateway on behalf of a signed-in person")
    else:
        try:
            p = person(person_token)
        except Exception as e:
            return reply(403, f"person not accepted: {type(e).__name__}")
        if team and p["team"] != team:
            return reply(403, f"person's team is {p['team']}, not {team}")
        team = p["team"]
    fresh = not (p.get("token") and time.time() < p["token_exp"] - 60)
    bearer = openai_token(p)
    pt = claims(person_token) if person_token else {}
    print(json.dumps({"event": "call", "team": team, "person": p["user_id"], "method": method, "path": "/" + rest, "bytes": len(body or b""),
                      "openai_token": "new" if fresh else "reused", "aws_jwt_jti": p.get("aws_jti"), "openai_jti": p.get("openai_jti"),
                      "person_token": {k: pt.get(k) for k in ("iss", "aud", "sub", "act", "cid", "team", "groups", "jti", "exp") if k in pt},
                      "sigv4_caller": ((event.get("requestContext") or {}).get("authorizer") or {}).get("iam", {}).get("userArn"),
                      "header_names": sorted(k for k in headers if k not in ("authorization", "x-person-token", "x-amz-security-token")),
                      "trace": {k: headers[k] for k in ("traceparent", "x-amzn-trace-id", "tracestate", "baggage") if k in headers}}))
    url = f"https://api.openai.com/{rest}" + (("?" + event["rawQueryString"]) if event.get("rawQueryString") else "")
    req = urllib.request.Request(url, data=body if method != "GET" else None, method=method, headers={
        "Authorization": f"Bearer {bearer}", "Content-Type": "application/json", "User-Agent": "openai-wif-translator/3.0"})
    try:
        with _HTTPS.open(req, timeout=60) as r:
            status, out, ctype = r.status, r.read(), r.headers.get("Content-Type", "application/json")
    except urllib.error.HTTPError as e:
        status, out, ctype = e.code, e.read(), e.headers.get("Content-Type", "application/json")
    return {"statusCode": status, "headers": {"Content-Type": ctype}, "body": out.decode(errors="replace")}
