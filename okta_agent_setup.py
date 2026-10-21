# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Okta for AI Agents (Cross App Access / ID-JAG) for the OBO-delegation flow. Needs OKTA_DOMAIN +
OKTA_API_TOKEN in config.env and your AWS profile (AWS_PROFILE) for the KMS key.

  AI agent         wif-openai-agent: a workload principal whose client authentication is private_key_jwt.
                   Its private key is an AWS KMS key (alias/openai-wif-agent) that never leaves KMS.
  Bound app        the agent's own OIDC app. People sign in here, so their id_token's aud = the agent
                   (Okta only delegates id_tokens issued to the agent itself).
  wif-openai-users existing auth server: adds scope openai-agent.invoke + a policy for the agent's app
                   (that access token is what AgentCore Runtime accepts).
  wif-gateway      new auth server whose tokens AgentCore Gateway accepts: sub = the person,
                   act = the agent, plus team (from the wif-* group), groups and login claims.
  Connection       the agent may get wif-gateway tokens with scope inference:invoke, only for the
                   wif-engineering / wif-finance groups (jwt-bearer grant).

Safe to re-run. Writes agent_state.json.
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import boto3
from cryptography.hazmat.primitives.serialization import load_der_public_key

# HTTPS only: urllib.request.urlopen would also open file:// and other schemes
_HTTPS = urllib.request.OpenerDirector()
for _h in (urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPRedirectHandler(),
           urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(), urllib.request.UnknownHandler()):
    _HTTPS.add_handler(_h)

HERE = Path(__file__).parent
STATE = HERE / "agent_state.json"
DOMAIN, TOKEN = os.environ.get("OKTA_DOMAIN", "").rstrip("/"), os.environ.get("OKTA_API_TOKEN", "")
if not (DOMAIN and TOKEN):
    sys.exit("Set OKTA_DOMAIN and OKTA_API_TOKEN in config.env")
WP = "/workload-principals/api/v1"
AGENT_NAME, KMS_ALIAS, KID = "wif-openai-agent", "alias/openai-wif-agent", "wif-openai-agent-kms"
REDIRECT, LOGOUT = "http://localhost:8090/callback", "http://localhost:8090/"
USERS_AS_NAME, GW_AS_NAME, GW_AUD = "wif-openai-users", "wif-gateway", "openai-wif-gateway"
INVOKE_SCOPE, GW_SCOPE = "openai-agent.invoke", "inference:invoke"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TEAM_EXPR = ('isMemberOfGroupName("wif-finance") ? "finance" : '
             '(isMemberOfGroupName("wif-engineering") ? "engineering" : null)')
AWS = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None, region_name=os.environ.get("AWS_REGION", "us-east-1"))


def call(method, path, body=None, params=None, ctype="application/json"):
    url = DOMAIN + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"SSWS {TOKEN}", "Accept": "application/json", "Content-Type": ctype})
    try:
        with _HTTPS.open(req, timeout=30) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path} -> {e.code}: {e.read().decode()[:600]}") from None


def items(r):
    return r.get("data", []) if isinstance(r, dict) else r


def by_name(path, name, key="name", params=None):
    return next((x for x in items(call("GET", path, params=params))
                 if (x.get("profile", {}).get("name") if key == "profile.name" else x.get(key)) == name), None)


def b64(n):
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


def kms_key():
    kms = AWS.client("kms")
    try:
        key_id = kms.describe_key(KeyId=KMS_ALIAS)["KeyMetadata"]["KeyId"]
    except kms.exceptions.NotFoundException:
        key_id = kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY",
                                Description="Okta AI agent wif-openai-agent: client-assertion signing key (private_key_jwt)",
                                Tags=[{"TagKey": "project", "TagValue": "openai-wif-demo"}])["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName=KMS_ALIAS, TargetKeyId=key_id)
    arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    pub = load_der_public_key(kms.get_public_key(KeyId=key_id)["PublicKey"]).public_numbers()
    return arn, {"kty": "RSA", "kid": KID, "alg": "RS256", "use": "sig", "e": b64(pub.e), "n": b64(pub.n)}


def scope(asid, name, desc):
    if not by_name(f"/api/v1/authorizationServers/{asid}/scopes", name):
        call("POST", f"/api/v1/authorizationServers/{asid}/scopes",
             {"name": name, "description": desc, "consent": "IMPLICIT", "metadataPublish": "NO_CLIENTS"})


def claim(asid, name, value, claim_type="RESOURCE", value_type="EXPRESSION", **extra):
    body = {"name": name, "status": "ACTIVE", "claimType": claim_type, "valueType": value_type, "value": value,
            "alwaysIncludeInToken": True, "conditions": {"scopes": []}, **extra}
    ex = by_name(f"/api/v1/authorizationServers/{asid}/claims", name)
    if ex and ex.get("claimType") == claim_type:
        call("PUT", f"/api/v1/authorizationServers/{asid}/claims/{ex['id']}", body)
    elif not ex:
        call("POST", f"/api/v1/authorizationServers/{asid}/claims", body)


def policy(asid, name, client_id, rules, lifetime=60):
    p = by_name(f"/api/v1/authorizationServers/{asid}/policies", name)
    if not p:
        p = call("POST", f"/api/v1/authorizationServers/{asid}/policies", {
            "type": "OAUTH_AUTHORIZATION_POLICY", "status": "ACTIVE", "name": name, "description": name,
            "priority": 1, "conditions": {"clients": {"include": [client_id]}}})
    existing = {r["name"]: r for r in call("GET", f"/api/v1/authorizationServers/{asid}/policies/{p['id']}/rules")}
    for i, (rname, groups, grants, scopes) in enumerate(rules, start=1):
        body = {"type": "RESOURCE_ACCESS", "name": rname, "priority": i, "status": "ACTIVE",
                "conditions": {"people": {"groups": {"include": groups}}, "grantTypes": {"include": grants}, "scopes": {"include": scopes}},
                "actions": {"token": {"accessTokenLifetimeMinutes": lifetime, "refreshTokenLifetimeMinutes": 0, "refreshTokenWindowMinutes": 10080}}}
        if rname in existing:
            call("PUT", f"/api/v1/authorizationServers/{asid}/policies/{p['id']}/rules/{existing[rname]['id']}", body)
        else:
            call("POST", f"/api/v1/authorizationServers/{asid}/policies/{p['id']}/rules", body)


def main():
    org_id = call("GET", "/api/v1/org")["id"]
    gids = {t: by_name("/api/v1/groups", f"wif-{t}", key="profile.name", params={"q": f"wif-{t}"})["id"] for t in ("engineering", "finance")}

    # 1. the AI agent + its bound OIDC app
    agent = next((a for a in items(call("GET", f"{WP}/ai-agents")) if a["profile"]["name"] == AGENT_NAME), None)
    if not agent:
        call("POST", f"{WP}/ai-agents", {"profile": {"name": AGENT_NAME, "description": "OpenAI WIF demo agent on AgentCore Runtime (Cross App Access / ID-JAG)"},
                                         "signOnProvider": {"type": "NEW_OIDC_APP"}})   # 202: created asynchronously
        for _ in range(12):
            time.sleep(5)
            agent = next((a for a in items(call("GET", f"{WP}/ai-agents")) if a["profile"]["name"] == AGENT_NAME), None)
            if agent and (agent.get("signOnProvider") or {}).get("appInstanceId"):
                break
    aid, client_id = agent["id"], agent["oauthClient"]["clientId"]
    print("AI agent:", aid, agent["status"], "client", client_id)

    key_arn, jwk = kms_key()
    if not any(j.get("kid") == KID for j in items(call("GET", f"{WP}/ai-agents/{aid}/credentials/jwks"))):
        call("POST", f"{WP}/ai-agents/{aid}/credentials/jwks", jwk)
    print("KMS key:", key_arn, "· public JWK", KID, "on the agent")

    app_id = agent["signOnProvider"]["appInstanceId"]
    app = call("GET", f"/api/v1/apps/{app_id}")
    app["settings"]["oauthClient"].update(redirect_uris=[REDIRECT], post_logout_redirect_uris=[LOGOUT])
    call("PUT", f"/api/v1/apps/{app_id}", app)
    if app["status"] != "ACTIVE":
        call("POST", f"/api/v1/apps/{app_id}/lifecycle/activate")
    for gid in gids.values():
        call("PUT", f"/api/v1/apps/{app_id}/groups/{gid}", {})
    signon = os.environ.get("OKTA_APP_SIGNON_POLICY", "")   # optional: an existing Okta app sign-in policy for the agent's app
    for pol in call("GET", "/api/v1/policies", params={"type": "ACCESS_POLICY"}) if signon else []:
        if pol.get("name") == signon:
            call("PUT", f"/api/v1/apps/{app_id}/policies/{pol['id']}")
    print("Bound app:", app_id, "redirect", REDIRECT, "· assigned to wif-engineering, wif-finance")

    # 2. sign-in server (existing): the token AgentCore Runtime accepts
    users_as = by_name("/api/v1/authorizationServers", USERS_AS_NAME)
    scope(users_as["id"], INVOKE_SCOPE, "Invoke the OpenAI WIF demo agent")
    policy(users_as["id"], AGENT_NAME, client_id, [
        ("teams-may-invoke", list(gids.values()), ["authorization_code"], ["openid", "profile", "email", INVOKE_SCOPE])])
    print("Sign-in server:", users_as["issuer"], "· scope", INVOKE_SCOPE, "for the agent's app")

    # 3. gateway server (new): the token AgentCore Gateway accepts
    gw_as = by_name("/api/v1/authorizationServers", GW_AS_NAME) or call("POST", "/api/v1/authorizationServers", {
        "name": GW_AS_NAME, "description": "OpenAI WIF demo: delegated tokens for AgentCore Gateway (sub = person, act = agent)",
        "audiences": [GW_AUD]})
    scope(gw_as["id"], GW_SCOPE, "Call OpenAI models through AgentCore Gateway")
    claim(gw_as["id"], "team", TEAM_EXPR)
    claim(gw_as["id"], "login", "user.login")
    claim(gw_as["id"], "groups", "wif-", value_type="GROUPS", group_filter_type="STARTS_WITH")   # the person's group membership
    as_orn = f"orn:okta:idp:{org_id}:authorization_servers:{gw_as['id']}"
    conns = items(call("GET", f"{WP}/ai-agents/{aid}/connections"))
    conn = next((c for c in conns if (c.get("authorizationServer") or {}).get("orn") == as_orn), None)
    if not conn:
        conn = call("POST", f"{WP}/ai-agents/{aid}/connections", {"connectionType": "IDENTITY_ASSERTION_CUSTOM_AS",
                    "authorizationServer": {"orn": as_orn}, "scopeCondition": "INCLUDE_ONLY", "scopes": [GW_SCOPE]})
    if conn.get("status") != "ACTIVE":
        call("POST", f"{WP}/ai-agents/{aid}/connections/{conn['id']}/lifecycle/activate")
    policy(gw_as["id"], AGENT_NAME, client_id, [("delegated-for-teams", list(gids.values()), [JWT_BEARER], [GW_SCOPE])])
    print("Gateway server:", gw_as["issuer"], "· aud", GW_AUD, "· claims team, login, groups · connection", conn["id"])

    if agent["status"] != "ACTIVE":
        call("POST", f"{WP}/ai-agents/{aid}/lifecycle/activate")
    st = json.loads(STATE.read_text()) if STATE.exists() else {}
    st["okta"] = {"org_id": org_id, "agent_id": aid, "client_id": client_id, "app_id": app_id, "kms_key_arn": key_arn, "kid": KID,
                  "redirect_uri": REDIRECT, "users_issuer": users_as["issuer"], "invoke_scope": INVOKE_SCOPE,
                  "gateway_issuer": gw_as["issuer"], "gateway_audience": GW_AUD, "gateway_scope": GW_SCOPE, "groups": gids}
    STATE.write_text(json.dumps(st, indent=1))
    print("AI agent active · state written to", STATE.name)


if __name__ == "__main__":
    main()
