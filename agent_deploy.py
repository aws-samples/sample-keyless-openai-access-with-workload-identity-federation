# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Deploy the Strands agent on AgentCore Runtime with Okta Cross App Access (needs okta_agent_setup.py and
gateway/gateway_obo.py up first). Uses your AWS profile (AWS_PROFILE, AWS_REGION in config.env).

  S3            openai-wif-agent-code-<acct>: private bucket for the code zip (block public access, SSE)
  Identity      workload identity openai-wif-agent-delegate + two CustomOauth2 providers that sign as the
                Okta AI agent with its KMS key (private_key_jwt, no client secret):
                  openai-wif-step1  Okta org AS · TOKEN_EXCHANGE          id_token -> ID-JAG
                  openai-wif-step2  Okta wif-gateway · JWT_AUTHORIZATION_GRANT   ID-JAG -> Gateway token
  IAM           OpenAIWifAgentRuntimeRole: its workload identity, the two providers, kms:Sign; no model access
  Runtime       openai_wif_agent (HTTP): CUSTOM_JWT inbound, only tokens issued to the agent's app (cid)

Usage: python agent_deploy.py up | test [ada|grace] | down

Scope: the GPT-5.6 models used here (Sol, Terra, Luna) are also generally available on Amazon Bedrock, where IAM, CloudWatch and Cost Explorer cover them natively; that is the simpler path for most workloads. This demo is for when you need OpenAI's own API (an existing OpenAI organization, projects and limits) without API keys.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path

import boto3

# HTTPS only: urllib.request.urlopen would also open file:// and other schemes
_HTTPS = urllib.request.OpenerDirector()
for _h in (urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPRedirectHandler(),
           urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(), urllib.request.UnknownHandler()):
    _HTTPS.add_handler(_h)

ROOT = Path(__file__).parent
S = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None, region_name=os.environ.get("AWS_REGION", "us-east-1"))
REG = S.region_name
ACCT = S.client("sts").get_caller_identity()["Account"]
iam, ac, s3 = S.client("iam"), S.client("bedrock-agentcore-control"), S.client("s3")
BUCKET, RT_NAME, ROLE = f"openai-wif-agent-code-{ACCT}", "openai_wif_agent", "OpenAIWifAgentRuntimeRole"
WORKLOAD, STEP1, STEP2 = "openai-wif-agent-delegate", "openai-wif-step1", "openai-wif-step2"
TAGS = {"project": "openai-wif-demo"}
STATE = ROOT / "agent_state.json"


def st():
    return json.loads(STATE.read_text())


def save(**kw):
    s = st(); s.setdefault("aws", {}).update(kw); STATE.write_text(json.dumps(s, indent=1))


def build():
    out = ROOT / "build" / "agent"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    subprocess.run(["uv", "pip", "install", "-q", "--target", str(out), "--python-platform", "aarch64-manylinux2014",
                    "--python-version", "3.13", "--only-binary", ":all:", "-r", str(ROOT / "agent" / "requirements.txt")], check=True)
    (out / "main.py").write_bytes((ROOT / "agent" / "main.py").read_bytes())
    zpath = ROOT / "build" / "agent.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for f in out.rglob("*"):
            if f.is_file() and "__pycache__" not in f.parts:
                z.write(f, f.relative_to(out))
    print(f"bundle {zpath.stat().st_size // 1_000_000} MB")
    return zpath


def bucket():
    try:
        s3.head_bucket(Bucket=BUCKET)
    except Exception:
        s3.create_bucket(Bucket=BUCKET)
        s3.put_public_access_block(Bucket=BUCKET, PublicAccessBlockConfiguration={k: True for k in (
            "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")})
        s3.put_bucket_encryption(Bucket=BUCKET, ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})
        s3.put_bucket_tagging(Bucket=BUCKET, Tagging={"TagSet": [{"Key": k, "Value": v} for k, v in TAGS.items()]})
    return BUCKET


def provider(name, discovery, grant, ok):
    obo = {"grantType": grant}
    if grant == "TOKEN_EXCHANGE":
        obo["tokenExchangeGrantTypeConfig"] = {"actorTokenContent": "NONE"}
    cfg = {"customOauth2ProviderConfig": {
        "oauthDiscovery": {"discoveryUrl": discovery}, "clientId": ok["client_id"], "clientAuthenticationMethod": "PRIVATE_KEY_JWT",
        "privateKeyJwtConfig": {"privateKeySource": {"kmsKeySource": {"kmsKeyArn": ok["kms_key_arn"]}},
                                "signingAlgorithm": "RS256", "additionalHeaderClaims": {"kid": ok["kid"]}},
        "onBehalfOfTokenExchangeConfig": obo}}
    try:
        ac.create_oauth2_credential_provider(name=name, credentialProviderVendor="CustomOauth2", oauth2ProviderConfigInput=cfg, tags=TAGS)
    except Exception as e:
        if "already exists" not in str(e) and "Conflict" not in type(e).__name__:
            raise
        ac.update_oauth2_credential_provider(name=name, credentialProviderVendor="CustomOauth2", oauth2ProviderConfigInput=cfg)


def role(ok):
    wid = f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:workload-identity-directory/default"
    vault = f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:token-vault/default"
    pol = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
         "Resource": f"arn:aws:logs:{REG}:{ACCT}:log-group:/aws/bedrock-agentcore/runtimes/*"},
        {"Effect": "Allow", "Action": "logs:DescribeLogGroups", "Resource": f"arn:aws:logs:{REG}:{ACCT}:log-group:*"},
        {"Effect": "Allow", "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["bedrock-agentcore:GetConfigurationBundle", "bedrock-agentcore:GetConfigurationBundleVersion"],
         "Resource": f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:configuration-bundle/*"},   # read the model from the configuration bundle
        {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*", "Condition": {"StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}}},
        {"Effect": "Allow", "Action": ["bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetWorkloadAccessTokenForJWT"],
         "Resource": [wid, f"{wid}/workload-identity/{RT_NAME}*", f"{wid}/workload-identity/{WORKLOAD}"]},
        {"Effect": "Allow", "Action": "bedrock-agentcore:GetResourceOauth2Token",
         "Resource": [vault, wid, f"{wid}/workload-identity/{WORKLOAD}", f"{vault}/oauth2credentialprovider/{STEP1}", f"{vault}/oauth2credentialprovider/{STEP2}"]},
        {"Effect": "Allow", "Action": "kms:Sign", "Resource": ok["kms_key_arn"]}]}
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole",
                                                                "Condition": {"StringEquals": {"aws:SourceAccount": ACCT}}}]})
    try:
        arn = iam.create_role(RoleName=ROLE, AssumeRolePolicyDocument=trust, Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
                              Description="OpenAI WIF demo agent: delegation via AgentCore Identity only; no model or AWS data access")["Role"]["Arn"]
        time.sleep(12)
    except iam.exceptions.EntityAlreadyExistsException:
        arn = iam.get_role(RoleName=ROLE)["Role"]["Arn"]
    iam.put_role_policy(RoleName=ROLE, PolicyName="openai-wif", PolicyDocument=json.dumps(pol))
    return arn


def wait_runtime(rid):
    for _ in range(120):
        s = ac.get_agent_runtime(agentRuntimeId=rid)["status"]
        if s in ("READY", "CREATE_FAILED", "UPDATE_FAILED"):
            return s
        time.sleep(5)
    return "TIMEOUT"


def up():
    s = st(); ok = s["okta"]
    gw = json.loads((ROOT / "gateway" / "state.json").read_text())
    zpath = build()
    s3.upload_file(str(zpath), bucket(), "agent.zip")
    print("code uploaded to private bucket", BUCKET)
    provider(STEP1, f"{os.environ['OKTA_DOMAIN'].rstrip('/')}/.well-known/openid-configuration", "TOKEN_EXCHANGE", ok)
    provider(STEP2, f"{ok['gateway_issuer']}/.well-known/openid-configuration", "JWT_AUTHORIZATION_GRANT", ok)
    try:
        ac.create_workload_identity(name=WORKLOAD, tags=TAGS)
    except Exception as e:
        if "already exists" not in str(e) and "Conflict" not in type(e).__name__:
            raise
    print(f"AgentCore Identity: {WORKLOAD} · {STEP1} (TOKEN_EXCHANGE) · {STEP2} (JWT_AUTHORIZATION_GRANT) · private_key_jwt via KMS {ok['kid']}")
    rarn = role(ok)
    print("runtime role", rarn)
    env = {"GATEWAY_INFERENCE_URL": gw["gw_url"].split("/mcp")[0] + "/inference/v1", "MODEL": "gpt-5.6-sol", "AGENT_CLIENT_ID": ok["client_id"],
           "WORKLOAD": WORKLOAD, "STEP1_PROVIDER": STEP1, "STEP2_PROVIDER": STEP2, "GATEWAY_ISSUER": ok["gateway_issuer"], "GATEWAY_SCOPE": ok["gateway_scope"]}
    auth = {"customJWTAuthorizer": {"discoveryUrl": f"{ok['users_issuer']}/.well-known/openid-configuration", "allowedAudience": ["openai-wif-demo"],
                                    "allowedScopes": [ok["invoke_scope"]],
                                    "customClaims": [{"inboundTokenClaimName": "cid", "inboundTokenClaimValueType": "STRING",
                                                      "authorizingClaimMatchValue": {"claimMatchOperator": "EQUALS", "claimMatchValue": {"matchValueString": ok["client_id"]}}}]}}
    kw = dict(agentRuntimeArtifact={"codeConfiguration": {"code": {"s3": {"bucket": BUCKET, "prefix": "agent.zip"}}, "runtime": "PYTHON_3_13", "entryPoint": ["main.py"]}},
              roleArn=rarn, networkConfiguration={"networkMode": "PUBLIC"}, protocolConfiguration={"serverProtocol": "HTTP"},
              authorizerConfiguration=auth, environmentVariables=env, requestHeaderConfiguration={"requestHeaderAllowlist": ["Authorization"]})
    found = next((r for r in ac.list_agent_runtimes().get("agentRuntimes", []) if r["agentRuntimeName"] == RT_NAME), None)
    if not found:
        for attempt in range(6):
            try:
                r = ac.create_agent_runtime(agentRuntimeName=RT_NAME, description="OpenAI WIF demo: Strands agent acting for the signed-in person", tags=TAGS, **kw)
                break
            except ac.exceptions.ValidationException as e:
                if "role" in str(e).lower() and attempt < 5:
                    time.sleep(10); continue
                raise
        rid, arn = r["agentRuntimeId"], r["agentRuntimeArn"]
    else:
        rid, arn = found["agentRuntimeId"], found["agentRuntimeArn"]
        wait_runtime(rid)
        ac.update_agent_runtime(agentRuntimeId=rid, **kw)
    status = wait_runtime(rid)
    save(runtime_id=rid, runtime_arn=arn, runtime_role=rarn, workload=WORKLOAD, step1=STEP1, step2=STEP2, bucket=BUCKET)
    print(f"runtime {RT_NAME} {rid}: {status}")
    if status != "READY":
        print(json.dumps(ac.get_agent_runtime(agentRuntimeId=rid).get("failureReason") or "", default=str)[:600])


def invoke(access_token, payload):
    arn = st()["aws"]["runtime_arn"]
    url = f"https://bedrock-agentcore.{REG}.amazonaws.com/runtimes/{urllib.parse.quote(arn, safe='')}/invocations?qualifier=DEFAULT"
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST", headers={
        "Authorization": f"Bearer {access_token}", "Content-Type": "application/json",
        "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": f"wif-{uuid.uuid4()}"})
    try:
        with _HTTPS.open(req, timeout=180) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")[:500]


def test(who="ada"):
    f = ROOT / "build" / f".chain_{'ada.lovelace' if who == 'ada' else 'grace.hopper'}.json"
    t = json.loads(f.read_text())
    for payload in ({"prompt": "What is 17 * 23? Also, what is today's date?", "id_token": t["id_token"]},
                    {"prompt": "Say hi.", "id_token": t["id_token"], "team_override": "finance" if who == "ada" else "engineering"}):
        code, out = invoke(t["access_token"], payload)
        label = "own team" if "team_override" not in payload else f"asks for {payload['team_override']}"
        if isinstance(out, dict) and out.get("ok"):
            tr = out["trace"]
            print(f"[{who} · {label}] HTTP {code} · {out['person']} · team {out['team']} · agent {out['agent']} · {out['total_ms']} ms")
            print("   answer:", out["answer"][:200].replace("\n", " "))
            print("   step1 ID-JAG claims:", json.dumps(tr["step1"]["id_jag"])[:160])   # the trace holds decoded claims, never token strings
            print("   step2 Gateway token claims:", json.dumps(tr["step2"]["gateway_token"])[:200])
            print("   model:", json.dumps(tr["model"])[:200])
        else:
            print(f"[{who} · {label}] HTTP {code} ·", json.dumps(out)[:500])


def down():
    s = st().get("aws", {})
    if s.get("runtime_id"):
        try:
            ac.delete_agent_runtime(agentRuntimeId=s["runtime_id"]); print("runtime deleted")
        except Exception as e:
            print("runtime", str(e)[:120])
    for n in (STEP1, STEP2):
        try:
            ac.delete_oauth2_credential_provider(name=n)
        except Exception:
            pass
    try:
        ac.delete_workload_identity(name=WORKLOAD)
    except Exception:
        pass
    try:
        iam.delete_role_policy(RoleName=ROLE, PolicyName="openai-wif"); iam.delete_role(RoleName=ROLE)
    except Exception:
        pass
    print("identity providers, workload identity, role removed (bucket kept:", BUCKET, ")")


if __name__ == "__main__":
    if os.environ.get("AWS_ACCOUNT_ID", ACCT) != ACCT:   # optional guard: AWS_ACCOUNT_ID in config.env
        sys.exit(f"your AWS profile is account {ACCT}, but config.env says AWS_ACCOUNT_ID={os.environ['AWS_ACCOUNT_ID']}")
    cmd = sys.argv[1]
    {"up": up, "down": down, "test": lambda: test(sys.argv[2] if len(sys.argv) > 2 else "ada")}[cmd]()
