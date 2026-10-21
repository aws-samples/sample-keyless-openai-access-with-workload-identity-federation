# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Direct pattern: a Strands agent on AgentCore Runtime calling OpenAI itself (no Gateway), AS THE PERSON.

  Inbound   Runtime CUSTOM_JWT: the signed-in person's Okta token (issued to the agent's app).
  Person    The agent hands that same Okta token to STS: AssumeRoleWithWebIdentity (IAM OIDC provider = Okta's
            sign-in server). The token is the credential. IAM is the mapping: the team role's trust admits it only
            if its team tag (from the Okta group) is that role's team. The session carries the person: source
            identity = login, session tags team + user.
  Model     Strands OpenAIModel with an OpenAI SDK client using workload_identity. The SDK's token function
            mints an AWS-signed JWT as the person's session (sub = team role, source_identity = the person);
            OpenAI exchanges it for the team's short-lived token. The agent's own role never gets one.
  Tools     local only: calculator, current_time.

Scope: the GPT-5.6 models used here (Sol, Terra, Luna) are also generally available on Amazon Bedrock, where IAM, CloudWatch and Cost Explorer cover them natively; that is the simpler path for most workloads. This demo is for when you need OpenAI's own API (an existing OpenAI organization, projects and limits) without API keys.
"""
import base64
import hashlib
import json
import os
import time

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from bedrock_agentcore.runtime import BedrockAgentCoreApp, BedrockAgentCoreContext
from openai import AsyncOpenAI
from strands import Agent
from strands.models.openai import OpenAIModel
from strands_tools import calculator, current_time

REGION = os.environ.get("AWS_REGION", "us-east-1")
TEAM_MODELS = json.loads(os.environ.get("TEAM_MODELS", '{"engineering": "gpt-5.6-sol", "finance": "gpt-5.6-terra"}'))   # default per team
PROVIDER_ID = os.environ["OPENAI_IDENTITY_PROVIDER_ID"]
TEAM_ROLES = json.loads(os.environ["TEAM_ROLES"])
SERVICE_ACCOUNTS = json.loads(os.environ["SERVICE_ACCOUNTS"])
STS_URL = f"https://sts.{REGION}.amazonaws.com"
PROMPT = ("You are a helpful assistant at AnyCompany running on AWS, acting for the signed-in person. Be brief. "
          "Use the calculator for arithmetic and current_time for dates and times.")

app = BedrockAgentCoreApp()
sts_anon = boto3.client("sts", region_name=REGION, endpoint_url=STS_URL, config=Config(signature_version=UNSIGNED))   # the token is the credential
TAG = "https://aws.amazon.com/tags/principal_tags/"
PEOPLE = {}   # sha256(okta token) -> person


def claims_of(tok):
    try:
        p = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def header_of(tok):
    try:
        h = tok.split(".")[0]
        return json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4)))
    except Exception:
        return {}


def person_for(okta_token):
    key = hashlib.sha256(okta_token.encode()).hexdigest()
    p = PEOPLE.get(key)
    if p and time.time() < p["exp"] - 1000:
        return p, True
    t0 = time.perf_counter()
    oc = claims_of(okta_token)
    team = oc.get(TAG + "team")                      # Okta's group -> team; IAM checks it fits the role
    if team not in TEAM_ROLES:
        raise PermissionError("the token carries no known team tag")
    login = oc.get("sub", "")
    a = sts_anon.assume_role_with_web_identity(RoleArn=TEAM_ROLES[team], WebIdentityToken=okta_token, DurationSeconds=3600,
                                               RoleSessionName=("person-" + "".join(ch if ch.isalnum() or ch in "+=,.@-_" else "-" for ch in login))[:64])
    c = a["Credentials"]
    uid = a.get("SourceIdentity") or login
    sess = boto3.client("sts", region_name=REGION, endpoint_url=STS_URL, aws_access_key_id=c["AccessKeyId"],
                        aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"])
    p = {"user_id": uid, "team": team, "exp": c["Expiration"].timestamp(), "session": a["AssumedRoleUser"]["Arn"], "mints": [],
         "identity_ms": round((time.perf_counter() - t0) * 1000),
         "web_identity": {"session": a["AssumedRoleUser"]["Arn"], "source_identity": a.get("SourceIdentity"), "subject": a.get("SubjectFromWebIdentityToken"),
                          "provider": a.get("Provider"), "audience": a.get("Audience"), "session_tags": {k[len(TAG):]: v for k, v in oc.items() if k.startswith(TAG)}}}

    def aws_token():    # the OpenAI SDK's subject-token provider: an AWS JWT for THIS person
        t1 = time.perf_counter()
        tok = sess.get_web_identity_token(Audience=["https://api.openai.com/v1"], SigningAlgorithm="ES384", DurationSeconds=900)["WebIdentityToken"]
        cl = claims_of(tok)
        ns = cl.get("https://sts.amazonaws.com/", {})
        p["mints"].append({"ms": round((time.perf_counter() - t1) * 1000), "claims": {"sub": cl.get("sub"), "aud": cl.get("aud"),
                           "source_identity": ns.get("source_identity"), "principal_tags": ns.get("principal_tags"),
                           "lifetime_s": cl.get("exp", 0) - cl.get("iat", 0)}, "full": cl})
        p["last_aws_jwt"] = cl
        p["last_aws_jwt_header"] = header_of(tok)
        return tok

    p["client"] = AsyncOpenAI(workload_identity={"identity_provider_id": PROVIDER_ID, "service_account_id": SERVICE_ACCOUNTS[team],
                                                 "provider": {"token_type": "jwt", "get_token": aws_token}})
    PEOPLE[key] = p
    return p, False


@app.entrypoint
async def invoke(payload, context):
    t_all = time.perf_counter()
    bearer = ((getattr(context, "request_headers", None) or {}).get("Authorization") or "")[7:]
    inbound = claims_of(bearer)
    trace = {"inbound": {k: inbound.get(k) for k in ("iss", "aud", "cid", "sub", "scp")}}
    try:
        p, cached = person_for(bearer)
    except Exception as e:
        return {"ok": False, "stage": "web_identity", "error": f"{type(e).__name__}: {e}"[:600], "trace": trace}
    before = len(p["mints"])
    trace["person"] = {"user": p["user_id"], "team": p["team"], "session": p["session"], "web_identity": p["web_identity"],
                       "cached": cached, "identity_ms": None if cached else p["identity_ms"],
                       "openai": {"identity_provider_id": PROVIDER_ID, "service_account_id": SERVICE_ACCOUNTS[p["team"]]}}
    try:   # the configuration bundle passed with this request (W3C baggage) sets the model
        cfg = BedrockAgentCoreContext.get_config_bundle() or {}
        ref = BedrockAgentCoreContext.get_config_bundle_ref()
        trace["bundle"] = {"name": getattr(ref, "bundle_id", None), "version": getattr(ref, "bundle_version", None), "model_id": cfg.get("model_id")}
    except Exception as e:
        cfg, trace["bundle"] = {}, {"error": f"{type(e).__name__}: {e}"[:200]}
    model_id = cfg.get("model_id") or payload.get("model") or TEAM_MODELS.get(p["team"], "gpt-5.6-sol")   # no Cedar here: only OpenAI's project limit decides
    agents = p.setdefault("agents", {})
    if model_id not in agents:   # one conversation per person and model (per sign-in)
        agents[model_id] = Agent(model=OpenAIModel(client=p["client"], model_id=model_id, params={"reasoning_effort": "none"}), tools=[calculator, current_time], system_prompt=PROMPT, callback_handler=None)
    agent = agents[model_id]
    t0 = time.perf_counter()
    try:
        result = await agent.invoke_async(payload.get("prompt") or "Say hello and tell me today's date.")
    except Exception as e:
        trace["mints"] = p["mints"][before:]
        trace["model"] = {"model_id": model_id, "endpoint": "https://api.openai.com/v1"}
        return {"ok": False, "stage": "model", "error": f"{type(e).__name__}: {e}"[:600], "trace": trace}
    usage = result.metrics.accumulated_usage if getattr(result, "metrics", None) else {}
    tools = list((getattr(result.metrics, "tool_metrics", {}) or {}).keys()) if getattr(result, "metrics", None) else []
    trace["mints"] = p["mints"][before:]
    trace["token_reused"] = not trace["mints"]
    trace["aws_jwt"] = p.get("last_aws_jwt")
    trace["aws_jwt_full"] = {"header": p.get("last_aws_jwt_header") or {}, "claims": p.get("last_aws_jwt")} if p.get("last_aws_jwt") else None
    try:   # the OpenAI SDK caches the exchanged token; show its claims (never the token)
        _t = p["client"]._workload_identity_auth._cached_token
        trace["openai_token"] = claims_of(_t)
        trace["openai_token_full"] = {"header": header_of(_t), "claims": claims_of(_t)}
    except Exception as e:
        trace["openai_token"] = {"unavailable": type(e).__name__}
    trace["model"] = {"model_id": model_id, "endpoint": "https://api.openai.com/v1", "ms": round((time.perf_counter() - t0) * 1000),
                      "usage": {"input_tokens": usage.get("inputTokens"), "output_tokens": usage.get("outputTokens")}, "tools_used": tools}
    return {"ok": True, "answer": str(result).strip(), "person": inbound.get("sub"), "team": p["team"], "trace": trace,
            "total_ms": round((time.perf_counter() - t_all) * 1000)}


if __name__ == "__main__":
    app.run()
