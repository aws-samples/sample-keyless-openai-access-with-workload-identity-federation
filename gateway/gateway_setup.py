# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AgentCore Gateway -> OpenAI with IAM all the way, and a short-lived OpenAI token only at the last hop.

  Gateway            openai-wif-gw · inbound AWS_IAM for now (Okta OBO comes later)
  Targets            openai-<team> · inference PROVIDER target · outbound GATEWAY_IAM_ROLE (SigV4, service=lambda)
  Translators        openai-wif-translator-<team> · Lambda Function URL (AWS_IAM) · role OpenAIWifGateway<Team>Role
                     its role -> sts:GetWebIdentityToken -> OpenAI token exchange -> api.openai.com
  OpenAI             sub-only mapping per role -> that team's service account

No OpenAI key and no vault entry. Usage:  python gateway_setup.py up | status | call | down
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import boto3
import botocore.auth
import botocore.awsrequest

# HTTPS only: urllib.request.urlopen would also open file:// and other schemes
_HTTPS = urllib.request.OpenerDirector()
for _h in (urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPRedirectHandler(),
           urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(), urllib.request.UnknownHandler()):
    _HTTPS.add_handler(_h)

HERE = Path(__file__).parent
STATE = HERE / "state.json"
PROFILE, REGION = os.environ.get("AWS_PROFILE") or None, os.environ.get("AWS_REGION", "us-east-1")
PROVIDER_ID = os.environ.get("OPENAI_IDENTITY_PROVIDER_ID", "")   # config.env
sas = lambda team: [s.strip() for s in os.environ.get(f"OPENAI_SA_{team.upper()}", "").split(",") if s.strip()]
TEAMS = {  # team -> (role, service account IDs from config.env, comma-separated; the first is used)
    "engineering": ("OpenAIWifGatewayEngineeringRole", sas("engineering")),
    "finance": ("OpenAIWifGatewayFinanceRole", sas("finance")),
}
GW_NAME, GW_ROLE = "openai-wif-gw", "OpenAIWifGatewayServiceRole"
TAGS = {"project": "openai-wif-demo"}
MODEL = "gpt-4.1-mini"

S = boto3.Session(profile_name=PROFILE, region_name=REGION)
iam, lam, ac, sts = S.client("iam"), S.client("lambda"), S.client("bedrock-agentcore-control"), S.client("sts")
ACCT = sts.get_caller_identity()["Account"]


def load():
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def save(st):
    STATE.write_text(json.dumps(st, indent=1))


def role(name, service, statements, tags, extra_trust=None):
    trust = [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}] + (extra_trust or [])
    doc = json.dumps({"Version": "2012-10-17", "Statement": trust})
    try:
        arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=doc, Tags=[{"Key": k, "Value": v} for k, v in tags.items()])["Role"]["Arn"]
    except iam.exceptions.EntityAlreadyExistsException:
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=doc)
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
    iam.put_role_policy(RoleName=name, PolicyName="openai-wif", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
    return arn


def http(url, body=None, headers=None, method=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers={"Content-Type": "application/json", "User-Agent": "openai-wif-setup/1.0", **(headers or {})})
    try:
        with _HTTPS.open(req, timeout=90) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")[:500]


def up():
    st = load()
    code = (HERE / "translator.py").read_bytes()
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("translator.py", code)
    st.setdefault("teams", {})

    # 1. team roles: may mint OpenAI-audience AWS tokens, nothing else.
    for team, (rname, _) in TEAMS.items():
        role(rname, "lambda.amazonaws.com", [
            {"Effect": "Allow", "Action": "sts:GetWebIdentityToken", "Resource": "*",
             "Condition": {"ForAllValues:StringEquals": {"sts:IdentityTokenAudience": "https://api.openai.com/v1"},
                           "NumericLessThanEquals": {"sts:DurationSeconds": 3600}}},
            {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
             "Resource": [f"arn:aws:logs:{REGION}:{ACCT}:log-group:/aws/lambda/openai-wif-translator-{team}",
                          f"arn:aws:logs:{REGION}:{ACCT}:log-group:/aws/lambda/openai-wif-translator-{team}:*"]}],
            {"team": team, **TAGS})
    print("team roles ready; waiting for IAM"); time.sleep(15)

    # 2. the service account each team role maps to at OpenAI (config.env; webid_setup.py test checks the exchange)
    for team, (rname, sas) in TEAMS.items():
        prev = st["teams"].setdefault(team, {}).get("sa")   # keep the one used last time, if any
        st["teams"][team]["sa"] = prev or (sas[0] if sas else None)
        print(f"  {team:11} -> OpenAI service account {st['teams'][team]['sa'] or '(set OPENAI_SA_' + team.upper() + ' in config.env)'}")
    save(st)

    # 3. translators (Lambda Function URL, IAM only)
    for team, (rname, _) in TEAMS.items():
        t = st["teams"][team]
        if not t["sa"]:
            print(f"  {team}: skipped (no OpenAI mapping accepts {rname})"); continue
        fn = f"openai-wif-translator-{team}"
        env = {"Variables": {"OPENAI_IDENTITY_PROVIDER_ID": PROVIDER_ID, "OPENAI_SERVICE_ACCOUNT_ID": t["sa"]}}
        try:
            t["fn"] = lam.create_function(FunctionName=fn, Runtime="python3.13", Role=f"arn:aws:iam::{ACCT}:role/{rname}", Handler="translator.handler",
                                          Code={"ZipFile": buf.getvalue()}, Timeout=60, MemorySize=256, Environment=env, Tags={**TAGS, "team": team})["FunctionArn"]
        except lam.exceptions.ResourceConflictException:
            t["fn"] = lam.update_function_code(FunctionName=fn, ZipFile=buf.getvalue())["FunctionArn"]
            lam.get_waiter("function_updated_v2").wait(FunctionName=fn)
            lam.update_function_configuration(FunctionName=fn, Environment=env)
        lam.get_waiter("function_active_v2").wait(FunctionName=fn)
        try:
            t["url"] = lam.create_function_url_config(FunctionName=fn, AuthType="AWS_IAM")["FunctionUrl"]
        except lam.exceptions.ResourceConflictException:
            t["url"] = lam.get_function_url_config(FunctionName=fn)["FunctionUrl"]
        print(f"  translator {team}: {t['url']}")
    save(st)

    # 4. gateway role: may call the translators' URLs, nothing else
    fns = [t["fn"] for t in st["teams"].values() if t.get("fn")]
    st["gw_role"] = role(GW_ROLE, "bedrock-agentcore.amazonaws.com",
                         [{"Effect": "Allow", "Action": ["lambda:InvokeFunctionUrl", "lambda:InvokeFunction"], "Resource": fns}], TAGS)
    time.sleep(12)

    # 5. gateway + one inference provider target per team
    if not st.get("gw"):
        g = ac.create_gateway(name=GW_NAME, roleArn=st["gw_role"], protocolType="MCP", authorizerType="AWS_IAM", tags=TAGS,
                              description="OpenAI via IAM: SigV4 to a translator that swaps its role for a short-lived OpenAI token")
        st["gw"], st["gw_url"] = g["gatewayId"], g["gatewayUrl"]
        save(st)
    for _ in range(60):
        if ac.get_gateway(gatewayIdentifier=st["gw"])["status"] in ("READY", "FAILED"):
            break
        time.sleep(5)
    for team, t in st["teams"].items():
        if not t.get("url") or t.get("target"):
            continue
        t["target"] = ac.create_gateway_target(
            gatewayIdentifier=st["gw"], name=f"openai-{team}",
            description=f"OpenAI for the {team} team, via translator role OpenAIWifGateway{team.title()}Role",
            targetConfiguration={"inference": {"provider": {"endpoint": t["url"].rstrip("/"),
                                                            "operations": [{"path": "/v1/responses", "models": [{"model": MODEL}]},
                                                                           {"path": "/v1/chat/completions", "models": [{"model": MODEL}]}]}}},
            credentialProviderConfigurations=[{"credentialProviderType": "GATEWAY_IAM_ROLE",
                                               "credentialProvider": {"iamCredentialProvider": {"service": "lambda", "region": REGION}}}])["targetId"]
        save(st)
    status()


def status():
    st = load()
    if not st.get("gw"):
        print("not deployed"); return
    print(f"gateway {st['gw']} · {ac.get_gateway(gatewayIdentifier=st['gw'])['status']} · {st['gw_url'].split('/mcp')[0]}/inference")
    for team, t in st.get("teams", {}).items():
        if not t.get("target"):
            print(f"  openai-{team}: not created (service account: {t.get('sa')})"); continue
        for _ in range(60):
            g = ac.get_gateway_target(gatewayIdentifier=st["gw"], targetId=t["target"])
            if g["status"] not in ("CREATING", "UPDATING", "SYNCHRONIZING"):
                break
            time.sleep(5)
        print(f"  openai-{team}: {g['status']} · SA {t['sa']} · {json.dumps(g.get('statusReasons') or '')[:200]}")


def call():
    st = load()
    base = st["gw_url"].split("/mcp")[0]
    creds = S.get_credentials().get_frozen_credentials()
    for team, t in st.get("teams", {}).items():
        if not t.get("target"):
            continue
        body = {"model": f"openai-{team}/{MODEL}", "input": f"In five words, greet the {team} team."}
        req = botocore.awsrequest.AWSRequest(method="POST", url=f"{base}/inference/v1/responses", data=json.dumps(body).encode(),
                                             headers={"Content-Type": "application/json"})
        botocore.auth.SigV4Auth(creds, "bedrock-agentcore", REGION).add_auth(req)
        c, out = http(f"{base}/inference/v1/responses", body, dict(req.headers), "POST")
        text = "".join(x.get("text", "") for o in (out.get("output") or []) if o.get("type") == "message" for x in o.get("content", [])) if isinstance(out, dict) else ""
        usage = out.get("usage", {}) if isinstance(out, dict) else {}
        print(f"  openai-{team}/{MODEL} -> HTTP {c} · {text or json.dumps(out)[:300]} · tokens in/out {usage.get('input_tokens')}/{usage.get('output_tokens')}")


def down():
    st = load()
    for team, t in st.get("teams", {}).items():
        if t.get("target"):
            try:
                ac.delete_gateway_target(gatewayIdentifier=st["gw"], targetId=t["target"]); print("deleted target", team)
            except Exception as e:
                print("target", team, e)
    if st.get("gw"):
        for _ in range(30):
            if not ac.list_gateway_targets(gatewayIdentifier=st["gw"]).get("items"):
                break
            time.sleep(5)
        ac.delete_gateway(gatewayIdentifier=st["gw"]); print("deleted gateway")
    for team in TEAMS:
        fn = f"openai-wif-translator-{team}"
        for f, what in [(lambda: lam.delete_function(FunctionName=fn), "function"),
                        (lambda: S.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn}"), "logs")]:
            try:
                f(); print("deleted", what, fn)
            except Exception:
                pass
    for rname in [GW_ROLE] + [r for r, _ in TEAMS.values()]:
        try:
            iam.delete_role_policy(RoleName=rname, PolicyName="openai-wif"); iam.delete_role(RoleName=rname); print("deleted role", rname)
        except Exception:
            pass
    STATE.unlink(missing_ok=True)


if __name__ == "__main__":
    if os.environ.get("AWS_ACCOUNT_ID", ACCT) != ACCT:   # optional guard: AWS_ACCOUNT_ID in config.env
        sys.exit(f"your AWS profile is account {ACCT}, but config.env says AWS_ACCOUNT_ID={os.environ['AWS_ACCOUNT_ID']}")
    {"up": up, "status": status, "call": call, "down": down}[sys.argv[1]]()
