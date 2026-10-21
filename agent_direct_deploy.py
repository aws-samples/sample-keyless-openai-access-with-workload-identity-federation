# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Deploy the Direct-pattern agent: Strands on AgentCore Runtime calling OpenAI itself (no Gateway).

  IAM       OpenAIWifDirectAgentRole: the Runtime's execution role and the agent's OpenAI identity.
            It may mint OpenAI-audience AWS tokens (sts:GetWebIdentityToken, <= 15 min), nothing else.
  OpenAI    a mapping  sub = arn:aws:iam::<acct>:role/OpenAIWifDirectAgentRole  ->  a service account
  Runtime   openai_wif_direct_agent (HTTP), same Okta inbound as the Gateway agent.

Usage: python agent_direct_deploy.py up | test [ada|grace] | down
"""
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
import zipfile
from pathlib import Path

import agent_deploy as A
import urllib.request

# HTTPS only: urllib.request.urlopen would also open file:// and other schemes
_HTTPS = urllib.request.OpenerDirector()
for _h in (urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPRedirectHandler(),
           urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(), urllib.request.UnknownHandler()):
    _HTTPS.add_handler(_h)

ROOT = Path(__file__).parent
ROLE, RT_NAME = "OpenAIWifDirectAgentRole", "openai_wif_direct_agent"
PROVIDER_ID = os.environ.get("OPENAI_IDENTITY_PROVIDER_ID", "")   # config.env


def build():
    out = ROOT / "build" / "agent_direct"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    subprocess.run(["uv", "pip", "install", "-q", "--target", str(out), "--python-platform", "aarch64-manylinux2014", "--python-version", "3.13",
                    "--only-binary", ":all:", "-r", str(ROOT / "agent_direct" / "requirements.txt")], check=True)
    (out / "main.py").write_bytes((ROOT / "agent_direct" / "main.py").read_bytes())
    z = ROOT / "build" / "agent_direct.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as f:
        for p in out.rglob("*"):
            if p.is_file() and "__pycache__" not in p.parts:
                f.write(p, p.relative_to(out))
    print(f"bundle {z.stat().st_size // 1_000_000} MB")
    return z


def role():
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                                                                "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"aws:SourceAccount": A.ACCT}}}]})
    try:
        arn = A.iam.create_role(RoleName=ROLE, AssumeRolePolicyDocument=trust, Tags=[{"Key": k, "Value": v} for k, v in A.TAGS.items()],
                                Description="Direct-pattern agent: acts for the PERSON with their Okta token (web identity); no OpenAI identity of its own")["Role"]["Arn"]
        time.sleep(12)
    except A.iam.exceptions.EntityAlreadyExistsException:
        arn = A.iam.get_role(RoleName=ROLE)["Role"]["Arn"]
    reg, acct = A.REG, A.ACCT
    A.iam.put_role_policy(RoleName=ROLE, PolicyName="openai-wif", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
         "Resource": f"arn:aws:logs:{reg}:{acct}:log-group:/aws/bedrock-agentcore/runtimes/*"},
        {"Effect": "Allow", "Action": "logs:DescribeLogGroups", "Resource": f"arn:aws:logs:{reg}:{acct}:log-group:*"},
        {"Effect": "Allow", "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules", "xray:GetSamplingTargets"], "Resource": "*"},
        {"Effect": "Allow", "Action": ["bedrock-agentcore:GetConfigurationBundle", "bedrock-agentcore:GetConfigurationBundleVersion"],
         "Resource": f"arn:aws:bedrock-agentcore:{reg}:{acct}:configuration-bundle/*"},   # read the model from the configuration bundle
        {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*", "Condition": {"StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}}}]}))
    return arn


def up(sa=None):
    ok = A.st()["okta"]
    gw = json.loads((ROOT / "gateway" / "state.json").read_text())
    z = build()
    A.s3.upload_file(str(z), A.bucket(), "agent_direct.zip")
    rarn = role()
    print("role", rarn, "(no OpenAI identity of its own: it acts as the person with their Okta token)")
    auth = {"customJWTAuthorizer": {"discoveryUrl": f"{ok['users_issuer']}/.well-known/openid-configuration", "allowedAudience": ["openai-wif-demo"],
                                    "allowedScopes": [ok["invoke_scope"]],
                                    "customClaims": [{"inboundTokenClaimName": "cid", "inboundTokenClaimValueType": "STRING",
                                                      "authorizingClaimMatchValue": {"claimMatchOperator": "EQUALS", "claimMatchValue": {"matchValueString": ok["client_id"]}}}]}}
    kw = dict(agentRuntimeArtifact={"codeConfiguration": {"code": {"s3": {"bucket": A.BUCKET, "prefix": "agent_direct.zip"}}, "runtime": "PYTHON_3_13", "entryPoint": ["main.py"]}},
              roleArn=rarn, networkConfiguration={"networkMode": "PUBLIC"}, protocolConfiguration={"serverProtocol": "HTTP"}, authorizerConfiguration=auth,
              environmentVariables={"OPENAI_IDENTITY_PROVIDER_ID": PROVIDER_ID, "TEAM_MODELS": json.dumps({"engineering": "gpt-5.6-sol", "finance": "gpt-5.6-terra"}),
                                    "TEAM_ROLES": json.dumps({t: f"arn:aws:iam::{A.ACCT}:role/OpenAIWifGateway{t.title()}Role" for t in ("engineering", "finance")}),
                                    "SERVICE_ACCOUNTS": json.dumps({t: v["sa"] for t, v in gw["teams"].items()}),
                                    },
              requestHeaderConfiguration={"requestHeaderAllowlist": ["Authorization"]})
    found = next((r for r in A.ac.list_agent_runtimes().get("agentRuntimes", []) if r["agentRuntimeName"] == RT_NAME), None)
    if not found:
        for attempt in range(6):
            try:
                r = A.ac.create_agent_runtime(agentRuntimeName=RT_NAME, description="OpenAI WIF demo: Strands agent calling OpenAI directly (no Gateway)", tags=A.TAGS, **kw)
                break
            except A.ac.exceptions.ValidationException as e:
                if "role" in str(e).lower() and attempt < 5:
                    time.sleep(10); continue
                raise
        rid, arn = r["agentRuntimeId"], r["agentRuntimeArn"]
    else:
        rid, arn = found["agentRuntimeId"], found["agentRuntimeArn"]
        A.wait_runtime(rid)
        A.ac.update_agent_runtime(agentRuntimeId=rid, **kw)
    status = A.wait_runtime(rid)
    s = A.st(); s["direct"] = {"runtime_id": rid, "runtime_arn": arn, "role": rarn, "acts_as": "the person (Identity Center)"}
    A.STATE.write_text(json.dumps(s, indent=1))
    print(f"runtime {RT_NAME} {rid}: {status}")


def test(who="ada"):
    import urllib.parse
    t = json.loads((ROOT / "build" / f".chain_{'ada.lovelace' if who == 'ada' else 'grace.hopper'}.json").read_text())
    arn = A.st()["direct"]["runtime_arn"]
    url = f"https://bedrock-agentcore.{A.REG}.amazonaws.com/runtimes/{urllib.parse.quote(arn, safe='')}/invocations?qualifier=DEFAULT"
    sid = f"wif-direct-{uuid.uuid4()}"
    for prompt in ("What is 19 * 21? Use the calculator.", "And plus 1?"):
        code, out = _post(url, {"prompt": prompt}, t["access_token"], sid)
        tr = out.get("trace", {}) if isinstance(out, dict) else {}
        print(f"HTTP {code} ok={out.get('ok') if isinstance(out, dict) else out} answer={str(out.get('answer', out.get('error', '')) if isinstance(out, dict) else '')[:120]!r}")
        print("   as person:", (tr.get("person") or {}).get("user"), "team", (tr.get("person") or {}).get("team"),
              "| AWS JWT:", json.dumps([m["claims"] for m in tr.get("mints", [])])[:260], "| reused:", tr.get("token_reused"))


def _post(url, body, bearer, sid):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={
        "Authorization": f"Bearer {bearer}", "Content-Type": "application/json", "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": sid})
    try:
        with _HTTPS.open(req, timeout=180) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")[:400]


def down():
    d = A.st().get("direct", {})
    if d.get("runtime_id"):
        try:
            A.ac.delete_agent_runtime(agentRuntimeId=d["runtime_id"]); print("runtime deleted")
        except Exception as e:
            print("runtime", str(e)[:120])
    try:
        A.iam.delete_role_policy(RoleName=ROLE, PolicyName="openai-wif"); A.iam.delete_role(RoleName=ROLE); print("role deleted")
    except Exception:
        pass


if __name__ == "__main__":
    if os.environ.get("AWS_ACCOUNT_ID", A.ACCT) != A.ACCT:   # optional guard: AWS_ACCOUNT_ID in config.env
        sys.exit(f"your AWS profile is account {A.ACCT}, but config.env says AWS_ACCOUNT_ID={os.environ['AWS_ACCOUNT_ID']}")
    cmd = sys.argv[1]
    if cmd == "up":
        up()
    else:
        {"test": lambda: test(sys.argv[2] if len(sys.argv) > 2 else "ada"), "down": down}[cmd]()
