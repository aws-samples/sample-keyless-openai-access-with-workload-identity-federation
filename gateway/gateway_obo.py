# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Turn the IAM Gateway into the OBO-delegation Gateway (run after gateway_setup.py up and okta_agent_setup.py).

  Inbound     CUSTOM_JWT: Okta wif-gateway tokens, aud openai-wif-gateway, scope inference:invoke,
              and cid must be the AI agent (only the agent can call, and only for someone).
  Target      ONE inference target `openai` -> the translator (GATEWAY_IAM_ROLE), every demo model listed.
  Cedar       per Okta group: the agent acting for a person (act names the agent) whose `groups` claim
              holds the group may call only that group's models (context.input.model).
  Person      each team target allowlists the X-Person-Token header (header propagation, no interceptor):
              the agent sends its delegated token there too, and the translator turns it into the person's
              IAM Identity Center identity.

Usage:  python gateway_obo.py up | test | down | retire-usage
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import boto3

# HTTPS only: urllib.request.urlopen would also open file:// and other schemes
_HTTPS = urllib.request.OpenerDirector()
for _h in (urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPRedirectHandler(),
           urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(), urllib.request.UnknownHandler()):
    _HTTPS.add_handler(_h)

HERE = Path(__file__).parent
ROOT = HERE.parent
S = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None, region_name=os.environ.get("AWS_REGION", "us-east-1"))
iam, lam, ac, ddb = S.client("iam"), S.client("lambda"), S.client("bedrock-agentcore-control"), S.client("dynamodb")
PERSON_HEADER = "X-Person-Token"
METADATA = {"allowedRequestHeaders": [PERSON_HEADER]}      # the only header the Gateway forwards to the translator
ACCT = S.client("sts").get_caller_identity()["Account"]
GSTATE = HERE / "state.json"
TABLE, ICPT, ICPT_ROLE, PE_NAME = "openai-wif-usage", "openai-wif-usage-interceptor", "OpenAIWifUsageInterceptorRole", "openai_wif_policies"
TAGS = {"project": "openai-wif-demo"}
ACTIONS = ["POST:/v1/responses", "POST:/v1/chat/completions"]
TARGET = "openai"
MODELS = ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"]
# Gateway (Cedar): the group decides the models. The first one is the group's default, and the only one its
# OpenAI project allows; luna passes Cedar but OpenAI's project limit refuses it (two independent layers).
GROUP_MODELS = {"wif-engineering": ["gpt-5.6-sol", "gpt-5.6-luna"],
                "wif-finance": ["gpt-5.6-terra", "gpt-5.6-luna"]}


def gst():
    return json.loads(GSTATE.read_text())


def okta():
    return json.loads((ROOT / "agent_state.json").read_text())["okta"]


def wait(fn, ok=("READY", "ACTIVE"), label=""):
    for _ in range(90):
        r = fn()
        s = r.get("status")
        if s in ok or (s and "FAIL" in s):
            return r
        time.sleep(5)
    raise TimeoutError(label)


def cedar(gw_arn, group, models, agent):
    acts = ", ".join(f'AgentCore::Action::"{TARGET}___{a}"' for a in ACTIONS)
    allowed = ", ".join(f'"{m}"' for m in models)
    return ("permit(\n  principal is AgentCore::OAuthUser,\n"
            f"  action in [{acts}],\n"
            f'  resource == AgentCore::Gateway::"{gw_arn}"\n'
            ") when {\n"
            f'  principal.hasTag("cid") && principal.getTag("cid") == "{agent}" &&\n'
            f'  principal.hasTag("act") && principal.getTag("act") like "*{agent}*" &&\n'
            f'  principal.hasTag("groups") && principal.getTag("groups") like "*\\"{group}\\"*" &&\n'
            f"  [{allowed}].contains(context.input.model)\n"
            "};")


def one_target(st):
    """The single inference target: every demo model, to the translator's root (it takes the team from the person)."""
    url = st["translator"]["url"].rstrip("/")
    cfg = {"inference": {"provider": {"endpoint": url, "operations": [
        {"path": a.split(":", 1)[1], "models": [{"model": m} for m in MODELS]} for a in ACTIONS]}}}
    kw = dict(name=TARGET, description="OpenAI via the translator: the person's Identity Center group picks the team role; Cedar picks the models",
              targetConfiguration=cfg, metadataConfiguration=METADATA,
              credentialProviderConfigurations=[{"credentialProviderType": "GATEWAY_IAM_ROLE",
                                                 "credentialProvider": {"iamCredentialProvider": {"service": "lambda", "region": S.region_name}}}])
    tid = (st.get("target") or {}).get("id")
    if tid:
        ac.update_gateway_target(gatewayIdentifier=st["gw"], targetId=tid, **kw)
    else:
        tid = ac.create_gateway_target(gatewayIdentifier=st["gw"], **kw)["targetId"]
    r = wait(lambda: ac.get_gateway_target(gatewayIdentifier=st["gw"], targetId=tid), label="target")
    st["target"] = {"name": TARGET, "id": tid, "url": url, "models": MODELS, "group_models": GROUP_MODELS}
    GSTATE.write_text(json.dumps(st, indent=1))
    print(f"target {TARGET} ({tid}) -> {url}: {r['status']} {json.dumps(r.get('statusReasons') or '')[:200]} · models {MODELS}")


def up():
    st, ok = gst(), okta()
    gw = ac.get_gateway(gatewayIdentifier=st["gw"])
    # 1. gateway role: + policy engine
    pol = json.loads(json.dumps(iam.get_role_policy(RoleName="OpenAIWifGatewayServiceRole", PolicyName="openai-wif")["PolicyDocument"]))
    pol["Statement"] = [s for s in pol["Statement"] if s.get("Sid") not in ("Interceptor", "Policy")] + [
        {"Sid": "Policy", "Effect": "Allow", "Action": ["bedrock-agentcore:GetPolicyEngine", "bedrock-agentcore:AuthorizeAction", "bedrock-agentcore:PartiallyAuthorizeActions"],
         "Resource": [f"arn:aws:bedrock-agentcore:us-east-1:{ACCT}:policy-engine/*", f"arn:aws:bedrock-agentcore:us-east-1:{ACCT}:gateway/*"]}]
    iam.put_role_policy(RoleName="OpenAIWifGatewayServiceRole", PolicyName="openai-wif", PolicyDocument=json.dumps(pol))
    # 2. a new gateway (an existing gateway's authorizer type can't change): Okta OBO tokens in
    authz = {"customJWTAuthorizer": {
        "discoveryUrl": f"{ok['gateway_issuer']}/.well-known/openid-configuration", "allowedAudience": [ok["gateway_audience"]],
        "allowedScopes": [ok["gateway_scope"]],
        "customClaims": [{"inboundTokenClaimName": "cid", "inboundTokenClaimValueType": "STRING",
                          "authorizingClaimMatchValue": {"claimMatchOperator": "EQUALS", "claimMatchValue": {"matchValueString": ok["client_id"]}}}]}}
    time.sleep(10)
    if st.get("inbound") != "CUSTOM_JWT":
        old = (st["gw"], {t: v.get("target") for t, v in st["teams"].items()})
        g = ac.create_gateway(name="openai-wif-obo-gw", roleArn=gw["roleArn"], protocolType="MCP", authorizerType="CUSTOM_JWT",
                              authorizerConfiguration=authz, tags=TAGS,
                              description="OpenAI via IAM; caller = the agent acting for a person (Okta Cross App Access)")
        st.update(gw=g["gatewayId"], gw_url=g["gatewayUrl"], inbound="CUSTOM_JWT", old_gw=old[0])
        GSTATE.write_text(json.dumps(st, indent=1))
        wait(lambda: ac.get_gateway(gatewayIdentifier=st["gw"]), label="new gateway")
        for team, t in st["teams"].items():
            t["target"] = ac.create_gateway_target(
                gatewayIdentifier=st["gw"], name=f"openai-{team}", description=f"OpenAI for the {team} team via translator role OpenAIWifGateway{team.title()}Role",
                targetConfiguration={"inference": {"provider": {"endpoint": t["url"].rstrip("/"), "operations": [
                    {"path": "/v1/responses", "models": [{"model": "gpt-4.1-mini"}]}, {"path": "/v1/chat/completions", "models": [{"model": "gpt-4.1-mini"}]}]}}},
                credentialProviderConfigurations=[{"credentialProviderType": "GATEWAY_IAM_ROLE",
                                                   "credentialProvider": {"iamCredentialProvider": {"service": "lambda", "region": S.region_name}}}],
                metadataConfiguration=METADATA)["targetId"]
            GSTATE.write_text(json.dumps(st, indent=1))
        for team, t in st["teams"].items():
            r = wait(lambda: ac.get_gateway_target(gatewayIdentifier=st["gw"], targetId=t["target"]), label="target")
            print(f"target openai-{team}: {r['status']}")
        # retire the IAM gateway (the translators stay)
        for tid in old[1].values():
            if tid:
                try:
                    ac.delete_gateway_target(gatewayIdentifier=old[0], targetId=tid)
                except Exception as e:
                    print("old target:", str(e)[:120])
        for _ in range(30):
            if not ac.list_gateway_targets(gatewayIdentifier=old[0]).get("items"):
                break
            time.sleep(5)
        try:
            ac.delete_gateway(gatewayIdentifier=old[0]); print("retired IAM gateway", old[0])
        except Exception as e:
            print("old gateway:", str(e)[:120])
    gw = ac.get_gateway(gatewayIdentifier=st["gw"])
    print("gateway", st["gw"], gw["status"], "· inbound CUSTOM_JWT (Okta wif-gateway, cid = agent)")
    if st.get("translator"):
        one_target(st)

    # 3. policy engine + one Cedar permit per team
    pe = next((p for p in ac.list_policy_engines().get("policyEngines", []) if p["name"] == PE_NAME), None) or \
        ac.create_policy_engine(name=PE_NAME, description="OpenAI WIF demo: team -> its OpenAI target, only via the agent", tags=TAGS)
    pe = wait(lambda: ac.get_policy_engine(policyEngineId=pe["policyEngineId"]), label="policy engine")
    have = {p["name"]: p for p in ac.list_policies(policyEngineId=pe["policyEngineId"]).get("policies", [])}
    for group, models in GROUP_MODELS.items():
        name, stmt = "group_" + group.replace("-", "_"), cedar(gw["gatewayArn"], group, models, ok["client_id"])
        for mode in ("FAIL_ON_ANY_FINDINGS", "IGNORE_ALL_FINDINGS"):
            try:
                if name in have:
                    ac.update_policy(policyEngineId=pe["policyEngineId"], policyId=have[name]["policyId"], definition={"cedar": {"statement": stmt}}, validationMode=mode)
                else:
                    ac.create_policy(policyEngineId=pe["policyEngineId"], name=name, definition={"cedar": {"statement": stmt}}, validationMode=mode)
                print(f"Cedar {name} ({mode})"); break
            except ac.exceptions.ValidationException as e:
                print(f"Cedar {name} {mode}: {str(e)[:200]}")
    for old in [p for n, p in have.items() if n.startswith("team_")]:      # replaced by the group rules
        ac.delete_policy(policyEngineId=pe["policyEngineId"], policyId=old["policyId"]); print("Cedar", old["name"], "replaced by the group rules")
    for _ in range(40):
        ps = ac.list_policies(policyEngineId=pe["policyEngineId"]).get("policies", [])
        if ps and all(p.get("status") == "ACTIVE" for p in ps):
            break
        time.sleep(3)
    print("policies:", [(p["name"], p.get("status")) for p in ac.list_policies(policyEngineId=pe["policyEngineId"]).get("policies", [])])
    # 4. attach Cedar in ENFORCE, no interceptors (an update restates the whole gateway)
    time.sleep(10)
    ac.update_gateway(gatewayIdentifier=st["gw"], name=gw["name"], roleArn=gw["roleArn"], protocolType=gw["protocolType"],
                      description=gw.get("description", ""), authorizerType="CUSTOM_JWT", authorizerConfiguration=authz,
                      policyEngineConfiguration={"arn": pe["policyEngineArn"], "mode": "ENFORCE"})
    g = wait(lambda: ac.get_gateway(gatewayIdentifier=st["gw"]), label="gateway update")
    st.update(pe_id=pe["policyEngineId"], pe_arn=pe["policyEngineArn"])
    for k in ("interceptor", "usage_table"):
        st.pop(k, None)
    GSTATE.write_text(json.dumps(st, indent=1))
    print("gateway", st["gw"], g["status"], "· Cedar ENFORCE attached · interceptors:", g.get("interceptorConfigurations") or "none")
    pol["Statement"] = [x for x in pol["Statement"] if x.get("Sid") != "Interceptor"]
    iam.put_role_policy(RoleName="OpenAIWifGatewayServiceRole", PolicyName="openai-wif", PolicyDocument=json.dumps(pol))


def post(url, body, token):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}", PERSON_HEADER: token})
    try:
        with _HTTPS.open(req, timeout=90) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")[:300]


def test():
    """With the delegated tokens from scripts/okta_chain_test.py: each person's allowed models 200, the others 403."""
    st = gst()
    base = st["gw_url"].split("/mcp")[0] + "/inference/v1/responses"
    for who in ("ada.lovelace", "grace.hopper"):
        f = ROOT / "build" / f".chain_{who}.json"
        if not f.exists():
            print(who, ": run scripts/okta_chain_test.py first"); continue
        tok = json.loads(f.read_text())["gateway_token"]
        p = tok.split(".")[1]
        groups = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))).get("groups")
        for m in MODELS:
            code, out = post(base, {"model": f"{TARGET}/{m}", "input": f"In five words, greet {who.split('.')[0].title()}."}, tok)
            text = "".join(x.get("text", "") for o in (out.get("output") or []) if o.get("type") == "message" for x in o.get("content", [])) if isinstance(out, dict) else ""
            print(f"  {who:13} {str(groups):20} -> {TARGET}/{m:13}: HTTP {code} · {text or json.dumps(out)[:150]}")
    print("  no token -> HTTP", post(base, {"model": f"{TARGET}/gpt-4.1-mini", "input": "hi"}, "x")[0])


def retire_usage():
    """Delete the earlier usage interceptor, its role and the DynamoDB usage table (no longer part of the demo)."""
    for f in (lambda: lam.delete_function(FunctionName=ICPT), lambda: S.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{ICPT}"),
              lambda: ddb.delete_table(TableName=TABLE),
              lambda: (iam.delete_role_policy(RoleName=ICPT_ROLE, PolicyName="openai-wif"), iam.delete_role(RoleName=ICPT_ROLE))):
        try:
            f()
        except Exception as e:
            print("  ", type(e).__name__, str(e)[:100])
    print("usage interceptor, its role and table", TABLE, "deleted")


def down():
    """Back to the IAM-only gateway (keeps the targets): detach Cedar and delete it."""
    st = gst()
    gw = ac.get_gateway(gatewayIdentifier=st["gw"])
    ac.update_gateway(gatewayIdentifier=st["gw"], name=gw["name"], roleArn=gw["roleArn"], protocolType=gw["protocolType"], authorizerType="AWS_IAM")
    wait(lambda: ac.get_gateway(gatewayIdentifier=st["gw"]), label="gateway")
    if st.get("pe_id"):
        for p in ac.list_policies(policyEngineId=st["pe_id"]).get("policies", []):
            ac.delete_policy(policyEngineId=st["pe_id"], policyId=p["policyId"])
        time.sleep(10)
        try:
            ac.delete_policy_engine(policyEngineId=st["pe_id"])
        except Exception as e:
            print("policy engine:", str(e)[:120])
    for k in ("pe_id", "pe_arn", "interceptor", "usage_table", "inbound"):
        st.pop(k, None)
    GSTATE.write_text(json.dumps(st, indent=1))
    print("gateway back to AWS_IAM")


if __name__ == "__main__":
    if os.environ.get("AWS_ACCOUNT_ID", ACCT) != ACCT:   # optional guard: AWS_ACCOUNT_ID in config.env
        sys.exit(f"your AWS profile is account {ACCT}, but config.env says AWS_ACCOUNT_ID={os.environ['AWS_ACCOUNT_ID']}")
    {"up": up, "test": test, "down": down, "retire-usage": retire_usage}[sys.argv[1]]()
