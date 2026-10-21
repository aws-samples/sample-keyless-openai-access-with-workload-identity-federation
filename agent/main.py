# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""OpenAI WIF demo agent: Strands on AgentCore Runtime, acting for the signed-in person.

  Inbound   Runtime CUSTOM_JWT: an Okta access token issued to this agent's own app (cid = the agent).
            Authorization is on the request-header allowlist, so the code can check it.
  Delegate  AgentCore Identity runs Okta Cross App Access, signing as the agent with its KMS key:
              step 1  id_token -> ID-JAG          (Okta org AS · token exchange)
              step 2  ID-JAG   -> Gateway token   (Okta wif-gateway · jwt-bearer)
            The Gateway token says sub = the person, act = this agent, team = their team.
  Model     OpenAI through AgentCore Gateway /inference (one target, `openai`), with that token as the bearer.
            Cedar reads the token's `groups` claim and allows only that group's models.
            The Gateway reaches OpenAI with IAM and forwards X-Person-Token (header propagation); a translator
            turns the person into a short-lived OpenAI token for them (IAM Identity Center).
  Tools     local only (strands-agents-tools): calculator, current_time.

No OpenAI key and no Okta client secret anywhere.
"""
import base64
import json
import os
import time

from bedrock_agentcore.identity.auth import requires_access_token
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.runtime.context import BedrockAgentCoreContext
from bedrock_agentcore.services.identity import IdentityClient
from strands import Agent
from strands.models.openai import OpenAIModel
from strands_tools import calculator, current_time

REGION = os.environ.get("AWS_REGION", "us-east-1")
GATEWAY_INFERENCE = os.environ["GATEWAY_INFERENCE_URL"]           # https://<gw>.gateway.bedrock-agentcore.<r>.amazonaws.com/inference/v1
MODEL = os.environ.get("MODEL", "gpt-5.6-sol")   # fallback only; the console sends the group's model
AGENT_CLIENT_ID = os.environ["AGENT_CLIENT_ID"]                   # the Okta AI agent (also the client of its own app)
WORKLOAD = os.environ["WORKLOAD"]                                 # standalone workload identity for the two steps
STEP1, STEP2 = os.environ["STEP1_PROVIDER"], os.environ["STEP2_PROVIDER"]
GATEWAY_ISSUER = os.environ["GATEWAY_ISSUER"]                     # Okta wif-gateway issuer (ID-JAG audience)
SCOPES = os.environ.get("GATEWAY_SCOPE", "inference:invoke").split()
STEP1_PARAMS = {"subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                "audience": GATEWAY_ISSUER}
PROMPT = ("You are a helpful assistant at AnyCompany. You run on AWS and act for the signed-in person. "
          "Be brief. Use the calculator for arithmetic and current_time for dates and times.")

app = BedrockAgentCoreApp()


def claims_of(tok):
    try:
        p = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


pick = lambda c, keys: {k: c.get(k) for k in keys if k in c}  # noqa: E731


def decoded(tok):
    """Header + claims of a JWT (never the signature), for the console's token walkthrough."""
    try:
        h = tok.split(".")[0]
        return {"header": json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4))), "claims": claims_of(tok)}
    except Exception:
        return None


# One AgentCore Identity provider per Okta step. Each uses the workload access token in the request
# context as its subject, so delegate() binds the step's subject first: the id_token, then the ID-JAG.
@requires_access_token(provider_name=STEP1, scopes=SCOPES, auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       custom_parameters=STEP1_PARAMS, force_authentication=True)
async def id_jag(*, access_token: str):
    return access_token


@requires_access_token(provider_name=STEP2, scopes=SCOPES, auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       force_authentication=True)
async def gateway_token(*, access_token: str):
    return access_token


async def delegate(id_token, bearer):
    """Cross App Access through AgentCore Identity. Returns (gateway token, trace with claims only)."""
    idc, inbound = claims_of(id_token), claims_of(bearer)
    trace = {"inbound": pick(inbound, ("iss", "aud", "cid", "uid", "scp", "sub")),
             "id_token": pick(idc, ("iss", "aud", "sub", "preferred_username"))}
    # the id_token must be the caller's own: same person, issued to this agent
    if not idc or idc.get("sub") != inbound.get("uid") or idc.get("aud") != AGENT_CLIENT_ID:
        raise PermissionError("id_token missing, or not the caller's own (sub/aud check)")
    identity = IdentityClient(REGION)

    def bind(jwt):
        BedrockAgentCoreContext.set_workload_access_token(
            identity.get_workload_access_token(WORKLOAD, user_token=jwt)["workloadAccessToken"])

    t0 = time.perf_counter()
    bind(id_token)
    jag = await id_jag()
    trace["step1"] = {"ms": round((time.perf_counter() - t0) * 1000),
                      "request": {"api": "GetResourceOauth2Token", "resourceCredentialProviderName": STEP1, "scopes": SCOPES,
                                  "oauth2Flow": "ON_BEHALF_OF_TOKEN_EXCHANGE", "customParameters": STEP1_PARAMS,
                                  "subject": "GetWorkloadAccessTokenForJWT(workload, id_token)"},
                      "id_jag": pick(claims_of(jag), ("iss", "aud", "sub", "client_id", "act", "scope", "exp")), "id_jag_full": decoded(jag)}
    t0 = time.perf_counter()
    bind(jag)
    tok = await gateway_token()
    trace["step2"] = {"ms": round((time.perf_counter() - t0) * 1000),
                      "request": {"api": "GetResourceOauth2Token", "resourceCredentialProviderName": STEP2, "scopes": SCOPES,
                                  "oauth2Flow": "ON_BEHALF_OF_TOKEN_EXCHANGE", "subject": "GetWorkloadAccessTokenForJWT(workload, ID-JAG)"},
                      "gateway_token": pick(claims_of(tok), ("iss", "aud", "sub", "uid", "cid", "act", "scp", "team", "groups", "login", "exp")),
                      "gateway_token_full": decoded(tok)}
    return tok, trace


def read_bundle():
    """The configuration bundle passed with this request (W3C baggage), if any: {name, version, model_id}."""
    try:
        cfg = BedrockAgentCoreContext.get_config_bundle() or {}
        ref = BedrockAgentCoreContext.get_config_bundle_ref()
        return {"name": getattr(ref, "bundle_id", None), "version": getattr(ref, "bundle_version", None), "model_id": cfg.get("model_id")}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"[:200]}


@app.entrypoint
async def invoke(payload, context):
    """payload: {"prompt": str, "id_token": str, "model": optional str (default gpt-4.1-mini; Cedar decides if the group may use it)}"""
    t_all = time.perf_counter()
    bearer = ((getattr(context, "request_headers", None) or {}).get("Authorization") or "")[7:]
    try:
        tok, trace = await delegate(payload.get("id_token", ""), bearer)
    except Exception as e:
        return {"ok": False, "stage": "delegation", "error": f"{type(e).__name__}: {e}"[:600]}
    team = trace["step2"]["gateway_token"].get("team")
    bundle = read_bundle()
    model_id = f"openai/{bundle.get('model_id') or payload.get('model') or MODEL}"   # the configuration bundle sets the model
    trace["bundle"] = bundle
    # Bearer = the delegated token (the Gateway validates it, Cedar decides). The same token goes in
    # X-Person-Token, the one header the targets allowlist, so the translator can find the person.
    model = OpenAIModel(client_args={"api_key": tok, "base_url": GATEWAY_INFERENCE, "default_headers": {"X-Person-Token": tok}}, model_id=model_id,
                        params={"reasoning_effort": "none"})   # gpt-5.6 + tools on chat/completions needs this
    agent = Agent(model=model, tools=[calculator, current_time], system_prompt=PROMPT, callback_handler=None)
    t0 = time.perf_counter()
    try:
        result = await agent.invoke_async(payload.get("prompt") or "Say hello and tell me today's date.")
    except Exception as e:
        trace["model"] = {"model_id": model_id, "error": f"{type(e).__name__}: {e}"[:600]}
        return {"ok": False, "stage": "model", "trace": trace, "error": trace["model"]["error"]}
    usage = result.metrics.accumulated_usage if getattr(result, "metrics", None) else {}
    tools = [name for name, m in (getattr(result.metrics, "tool_metrics", {}) or {}).items()] if getattr(result, "metrics", None) else []
    trace["model"] = {"model_id": model_id, "gateway": GATEWAY_INFERENCE, "ms": round((time.perf_counter() - t0) * 1000),
                      "usage": {"input_tokens": usage.get("inputTokens"), "output_tokens": usage.get("outputTokens")}, "tools_used": tools}
    return {"ok": True, "answer": str(result).strip(), "person": trace["step2"]["gateway_token"].get("sub"), "team": team,
            "agent": (trace["step2"]["gateway_token"].get("act") or {}).get("sub"), "trace": trace,
            "total_ms": round((time.perf_counter() - t_all) * 1000)}


if __name__ == "__main__":
    app.run()
