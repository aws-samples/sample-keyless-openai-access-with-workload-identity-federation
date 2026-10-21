# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Local console (http://localhost:8090) for Okta -> AgentCore Runtime agent -> AgentCore Gateway -> OpenAI.

Signs a person in to the Okta AI agent's own app (authorization code + PKCE; the client assertion is
signed by the agent's KMS key, so there is no client secret). Keeps their tokens in memory only. Each run
invokes the agent on AgentCore Runtime with them; the agent does the delegation and the model call.
This process never talks to OpenAI and holds no OpenAI credential.
"""
import base64
import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import boto3

# HTTPS only: urllib.request.urlopen would also open file:// and other schemes
_HTTPS = urllib.request.OpenerDirector()
for _h in (urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPRedirectHandler(),
           urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(), urllib.request.UnknownHandler()):
    _HTTPS.add_handler(_h)

HERE = Path(__file__).parent
ROOT = HERE.parent
WEB = HERE / "web"
PORT = 8090
BASE = f"http://localhost:{PORT}"
REG = os.environ.get("AWS_REGION", "us-east-1")
S = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None, region_name=REG)
kms, ac, sts, iam = S.client("kms"), S.client("bedrock-agentcore-control"), S.client("sts"), S.client("iam")
logs, trail, idstore = S.client("logs"), S.client("cloudtrail"), S.client("identitystore")
xray = S.client("xray")
_OBS = {"at": 0, "v": None}
TRANSLATOR_LOGS = "/aws/lambda/openai-wif-translator"
SESSION = {"id_token": None, "access_token": None, "pending": {}, "last": None}
ASSERT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def cfg():
    a = json.loads((ROOT / "agent_state.json").read_text()) if (ROOT / "agent_state.json").exists() else {}
    g = json.loads((ROOT / "gateway" / "state.json").read_text()) if (ROOT / "gateway" / "state.json").exists() else {}
    return a.get("okta", {}), a.get("aws", {}), g


def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def claims_of(tok):
    try:
        p = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return {}


def client_assertion(aud):
    """private_key_jwt for the agent's app, signed by its KMS key (the private key never leaves KMS)."""
    ok = cfg()[0]
    now = int(time.time())
    si = f"{b64u(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': ok['kid']}).encode())}." \
         f"{b64u(json.dumps({'iss': ok['client_id'], 'sub': ok['client_id'], 'aud': aud, 'iat': now, 'exp': now + 300, 'jti': str(uuid.uuid4())}).encode())}"
    sig = kms.sign(KeyId=ok["kms_key_arn"], Message=hashlib.sha256(si.encode()).digest(), MessageType="DIGEST",
                   SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256")["Signature"]
    return f"{si}.{b64u(sig)}"


def http(url, body=None, headers=None, method="POST", timeout=180):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with _HTTPS.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")[:500]


def decoded(tok):
    """Header + claims of a JWT (never the signature)."""
    try:
        h = tok.split(".")[0]
        return {"header": json.loads(base64.urlsafe_b64decode(h + "=" * (-len(h) % 4))), "claims": claims_of(tok)}
    except Exception:
        return None


def signed_in():
    c = claims_of(SESSION["id_token"] or "")
    if not c or c.get("exp", 0) < time.time() + 30:
        SESSION.update(id_token=None, access_token=None)
        return None
    return c


_IDC = {}


def idc_person(login):
    """The signed-in person as IAM Identity Center knows them (user ID + wif-* groups), for the screens."""
    if not login:
        return {}
    if login in _IDC:
        return _IDC[login]
    try:
        st = json.loads((ROOT / "agent_state.json").read_text()).get("idc") or {}
        ids = S.client("identitystore")
        uid = ids.get_user_id(IdentityStoreId=st["identity_store"], AlternateIdentifier={"UniqueAttribute": {"AttributePath": "userName", "AttributeValue": login}})["UserId"]
        gids = {m["GroupId"] for m in ids.list_group_memberships_for_member(IdentityStoreId=st["identity_store"], MemberId={"UserId": uid})["GroupMemberships"]}
        groups = [f"wif-{t}" for t, g in st.get("groups", {}).items() if g in gids]
        _IDC[login] = {"idc_user_id": uid, "idc_groups": groups}
    except Exception as e:
        _IDC[login] = {"idc_error": str(e)[:120]}
    return _IDC[login]


def person_team():
    """The team as Okta states it on the id_token (from the wif-* group)."""
    return claims_of(SESSION["id_token"] or "").get("https://aws.amazon.com/tags/principal_tags/team") or (SESSION.get("last") or {}).get("team")


def bundle_headers(model):
    """W3C baggage that tells AgentCore which configuration bundle (and version) this request uses."""
    b = (json.loads((ROOT / "agent_state.json").read_text()).get("bundles") or {}).get(model or "")
    return {"baggage": f"aws.agentcore.configbundle_arn={b['arn']},aws.agentcore.configbundle_version={b['version']}"} if b else {}


def invoke_direct(payload, headers=None):
    """The Direct-pattern agent. One Runtime session per console sign-in, so the OpenAI SDK's cached token is reused."""
    d = json.loads((ROOT / "agent_state.json").read_text())["direct"]
    sid = SESSION.get("direct_sid") or f"wif-direct-{uuid.uuid4()}"   # sign-in/out reset it to None
    SESSION["direct_sid"] = sid
    url = f"https://bedrock-agentcore.{REG}.amazonaws.com/runtimes/{urllib.parse.quote(d['runtime_arn'], safe='')}/invocations?qualifier=DEFAULT"
    t0 = time.perf_counter()
    code, out = http(url, payload, {"Authorization": f"Bearer {SESSION['access_token']}", "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": sid, **(headers or {})})
    return code, out, round((time.perf_counter() - t0) * 1000)


def invoke_agent(payload, access_token=None, headers=None):
    arn = cfg()[1]["runtime_arn"]
    url = f"https://bedrock-agentcore.{REG}.amazonaws.com/runtimes/{urllib.parse.quote(arn, safe='')}/invocations?qualifier=DEFAULT"
    t0 = time.perf_counter()
    code, out = http(url, {**payload, "id_token": SESSION["id_token"]}, {
        "Authorization": f"Bearer {access_token or SESSION['access_token']}", "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": f"wif-console-{uuid.uuid4()}", **(headers or {})})
    return code, out, round((time.perf_counter() - t0) * 1000)


_NAMES = {}


def user_name(uid):
    """The person behind an ID: with web identity it is already the login (source identity)."""
    if not uid or uid == "gateway-discovery":
        return None
    if "@" in uid:
        return uid
    if uid not in _NAMES:
        try:
            store = json.loads((ROOT / "agent_state.json").read_text())["idc"]["identity_store"]
            _NAMES[uid] = idstore.describe_user(IdentityStoreId=store, UserId=uid)["UserName"]
        except Exception:
            _NAMES[uid] = None
    return _NAMES[uid]


def evidence(since):
    """What AWS itself recorded about who each OpenAI token was for, since `since` (epoch seconds).
    translator: its CloudWatch log (seconds). cloudtrail: AssumeRoleWithWebIdentity + GetWebIdentityToken (minutes)."""
    out = {"since": since, "now": time.time(), "translator": [], "cloudtrail": []}
    try:
        evs, kw = [], {}
        for _ in range(10):   # results come stream by stream; page until done
            r = logs.filter_log_events(logGroupName=TRANSLATOR_LOGS, startTime=int(since * 1000),
                                       filterPattern='{ $.event = "aws_jwt_minted" || $.event = "call" }', **kw)
            evs += r.get("events", [])
            if not r.get("nextToken"):
                break
            kw = {"nextToken": r["nextToken"]}
        for e in evs:
            m = json.loads(e["message"])
            if m.get("person") != "gateway-discovery":
                out["translator"].append({**m, "ts": e["timestamp"] / 1000, "user": user_name(m.get("person"))})
    except Exception as e:
        out["translator_error"] = f"{type(e).__name__}: {e}"[:160]
    for name in ("GetWebIdentityToken", "AssumeRoleWithWebIdentity"):
        try:
            r = trail.lookup_events(LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}], MaxResults=25,
                                    StartTime=datetime.fromtimestamp(since - 120, timezone.utc))
        except Exception as e:
            out["cloudtrail_error"] = f"{type(e).__name__}: {e}"[:160]
            continue
        for ev in r.get("Events", []):
            e = json.loads(ev["CloudTrailEvent"])
            u, rq, rs = e.get("userIdentity", {}), e.get("requestParameters") or {}, e.get("responseElements") or {}
            if name == "GetWebIdentityToken":
                caller, who, field = u.get("arn", ""), (u.get("sessionContext") or {}).get("sourceIdentity"), "userIdentity.sessionContext.sourceIdentity"
            else:   # the Okta token itself is the credential: no AWS caller, the person is in the response
                caller, who, field = rq.get("roleArn", ""), rs.get("sourceIdentity") or u.get("userName"), "responseElements.sourceIdentity"
            if "OpenAIWif" not in caller:
                continue
            out["cloudtrail"].append({"event": name, "ts": ev["EventTime"].timestamp(), "event_id": e.get("eventID"), "caller": caller, "field": field,
                                      "user_id": who, "user": who, "provider": u.get("identityProvider"), "audience": rq.get("audience")})
    for k in ("translator", "cloudtrail"):
        out[k].sort(key=lambda x: x["ts"], reverse=True)
    return out


def observability(gw_id):
    """Transaction Search + the Gateway's log/trace deliveries (cached a minute; read-only)."""
    if time.time() - _OBS["at"] < 60 and _OBS["v"] is not None:
        return _OBS["v"]
    v = {}
    try:
        d = xray.get_trace_segment_destination()
        v["destination"], v["destination_status"] = d.get("Destination"), d.get("Status")
        kinds = {x["deliverySourceName"]: x.get("deliveryDestinationType") for x in logs.describe_deliveries()["deliveries"]}
        v["gateway_logs"] = kinds.get(f"{gw_id}-logs") == "CWL"
        v["gateway_traces"] = kinds.get(f"{gw_id}-traces") == "XRAY"
        v["log_group"] = f"/aws/vendedlogs/bedrock-agentcore/gateway/APPLICATION_LOGS/{gw_id}"
    except Exception as e:
        v["error"] = str(e)[:120]
    _OBS.update(at=time.time(), v=v)
    return v


def setup_info(ok):
    """What the Setup screens check: config.env presence (never the token itself) and what the scripts recorded."""
    users = lambda k: [u.strip() for u in os.environ.get(k, "").split(",") if u.strip()]
    return {"okta_domain": os.environ.get("OKTA_DOMAIN", "").replace("https://", "").rstrip("/") or None,
            "okta_token": bool(os.environ.get("OKTA_API_TOKEN")), "people": {"engineering": users("OKTA_ENGINEERING_USERS"), "finance": users("OKTA_FINANCE_USERS")},
            "groups": ok.get("groups") or {}, "app_id": ok.get("app_id"), "org_id": ok.get("org_id"), "gateway_scope": ok.get("gateway_scope"),
            "invoke_scope": ok.get("invoke_scope"), "redirect_uri": ok.get("redirect_uri")}


def status():
    ok, aw, g = cfg()
    s = {"region": REG, "okta": {"configured": bool(ok.get("client_id")), "agent": ok.get("client_id"), "users_issuer": ok.get("users_issuer"),
                                 "gateway_issuer": ok.get("gateway_issuer"), "kid": ok.get("kid"), "kms": ok.get("kms_key_arn")}}
    c = signed_in()
    if c:
        s["user"] = {"login": c.get("preferred_username"), "sub": c.get("sub"), "team": person_team(), "groups": [f"wif-{person_team()}"] if person_team() else []}
    try:
        s["account"] = sts.get_caller_identity()["Account"]
    except Exception as e:
        s["error"] = f"No AWS credentials: {e}"
        return s
    try:
        s["federation"] = iam.get_outbound_web_identity_federation_info()["IssuerIdentifier"]
    except Exception:
        s["federation"] = None
    wid = json.loads((ROOT / "agent_state.json").read_text()).get("webid") if (ROOT / "agent_state.json").exists() else None
    if wid:
        s["webid"] = wid
    s["bundles"] = (json.loads((ROOT / "agent_state.json").read_text()).get("bundles") if (ROOT / "agent_state.json").exists() else None) or {}
    s["openai_map"] = g.get("openai")
    s["setup"] = setup_info(ok)
    if g.get("gw"):
        s["observability"] = observability(g["gw"])
    if g.get("gw"):
        try:
            gw = ac.get_gateway(gatewayIdentifier=g["gw"])
            s["gateway"] = {"id": g["gw"], "status": gw["status"], "auth": gw.get("authorizerType"), "url": g["gw_url"].split("/mcp")[0] + "/inference",
                            "policy": (gw.get("policyEngineConfiguration") or {}).get("mode"),
                            "teams": {t: {"sa": v.get("sa")} for t, v in g.get("teams", {}).items()},
                            "target": (g.get("target") or {}).get("name"), "models": (g.get("target") or {}).get("models", []),
                            "group_models": (g.get("target") or {}).get("group_models", {})}
        except Exception as e:
            s["gateway"] = {"error": str(e)[:120]}
    d = json.loads((ROOT / "agent_state.json").read_text()).get("direct", {}) if (ROOT / "agent_state.json").exists() else {}
    if d.get("runtime_id"):
        try:
            rt = ac.get_agent_runtime(agentRuntimeId=d["runtime_id"])
            s["direct"] = {"id": d["runtime_id"], "status": rt["status"], "role": d.get("role"), "service_account_id": d.get("service_account_id")}
        except Exception as e:
            s["direct"] = {"error": str(e)[:120]}
    if aw.get("runtime_id"):
        try:
            rt = ac.get_agent_runtime(agentRuntimeId=aw["runtime_id"])
            s["runtime"] = {"id": aw["runtime_id"], "status": rt["status"], "role": aw.get("runtime_role"), "workload": aw.get("workload"),
                            "providers": [aw.get("step1"), aw.get("step2")]}
        except Exception as e:
            s["runtime"] = {"error": str(e)[:120]}
    return s


# ------------------------------------------------------------------ runs (each yields NDJSON events)
def err_code(err):
    import re
    m = re.search(r"Error code: (\d{3})", err or "")
    return int(m.group(1)) if m else None


def from_agent(code, out, ms, label=None):
    if not isinstance(out, dict):
        yield {"kind": "hop", "edge": "agent", "status": code, "ms": ms}
        yield {"kind": "result", "data": {"ok": False, "stage": "runtime", "http": code, "error": out, "label": label}}
        return
    tr = out.get("trace") or {}
    yield {"kind": "hop", "edge": "agent", "status": 200 if code == 200 else code, "ms": ms}
    if "step1" in tr:
        yield {"kind": "hop", "edge": "step1", "status": "ok", "ms": tr["step1"].get("ms")}
    elif out.get("stage") == "delegation":
        yield {"kind": "hop", "edge": "step1", "status": "denied"}
    if "step2" in tr:
        yield {"kind": "hop", "edge": "step2", "status": "ok", "ms": tr["step2"].get("ms")}
    if "model" in tr:
        err = tr["model"].get("error") or ""
        cedar = "policy enforcement" in err            # the Gateway's own denial; anything else came back from OpenAI
        yield {"kind": "hop", "edge": "gateway", "status": 403 if cedar else (500 if err and not err_code(err) else 200), "ms": tr["model"].get("ms")}
        if not cedar and (not err or err_code(err)):
            yield {"kind": "hop", "edge": "openai", "status": err_code(err) if err else 200, "model": tr["model"].get("model_id")}
    SESSION["last"] = out
    yield {"kind": "result", "data": {**out, "http": code, "client_ms": ms, "label": label}}


def translator_tokens(since, uid, wait=20):
    """The translator's own log for this person's latest call: which tokens it used (claims only)."""
    q = '{ $.person = "%s" }' % uid
    for _ in range(wait // 2):
        evs, kw = [], {}
        for _ in range(10):
            r = logs.filter_log_events(logGroupName=TRANSLATOR_LOGS, startTime=int((since - 3600) * 1000), filterPattern=q, **kw)
            evs += r.get("events", [])
            if not r.get("nextToken"):
                break
            kw = {"nextToken": r["nextToken"]}
        recs = sorted((dict(json.loads(e["message"]), ts=e["timestamp"] / 1000) for e in evs), key=lambda x: x["ts"])
        calls = [x for x in recs if x["event"] == "call" and x["ts"] >= since - 2]
        if calls:
            call = calls[-1]
            find = lambda ev, jti: next((x for x in reversed(recs) if x["event"] == ev and x.get("jti") == jti), None)  # noqa: E731
            wi = next((x for x in reversed(recs) if x["event"] == "web_identity" and x["ts"] <= call["ts"] + 1), None)
            aws, oai = find("aws_jwt_minted", call.get("aws_jwt_jti")), find("openai_token_issued", call.get("openai_jti"))
            return {"call": call, "web_identity": wi and {k: v for k, v in wi.items() if k not in ("ts", "event")},
                    "aws_jwt_full": aws and {"header": aws.get("header"), "claims": aws.get("claims")},
                    "openai_token_full": oai and {"header": oai.get("header"), "claims": oai.get("claims"), "expires_in": oai.get("expires_in")},
                    "aws_jwt": aws and aws.get("claims"), "aws_jwt_at": aws and aws["ts"],
                    "openai_token": oai and oai.get("claims"), "openai_token_at": oai and oai["ts"], "openai_expires_in": oai and oai.get("expires_in")}
        time.sleep(2)
    return None


def run_chat(body):
    t0 = time.time()
    yield {"kind": "hop", "edge": "agent", "status": "sending"}
    g = cfg()[2].get("target") or {}
    default = ((g.get("group_models") or {}).get(f"wif-{person_team() or 'engineering'}") or [None])[0]
    if body.get("bundle"):   # the configuration bundle decides the model; the payload carries none
        code, out, ms = invoke_agent({"prompt": body.get("prompt") or ""}, headers=bundle_headers(body["bundle"]))
    else:
        code, out, ms = invoke_agent({"prompt": body.get("prompt") or "", "model": body.get("model") or default})
    if isinstance(out, dict) and out.get("ok"):
        uid = (claims_of(SESSION["id_token"] or "")).get("preferred_username")      # the source identity the translator logs
        if uid:
            try:
                out["translator"] = translator_tokens(t0, uid)
            except Exception as e:
                out["translator"] = {"error": f"{type(e).__name__}: {e}"[:160]}
            tr, x = out.get("trace") or {}, out.get("translator") or {}
            SESSION["chain"] = {"at": time.time(), "login": SESSION.get("login"), "id_token": decoded(SESSION["id_token"]), "access_token": decoded(SESSION["access_token"]),
                                "id_jag": (tr.get("step1") or {}).get("id_jag_full"), "step1_request": (tr.get("step1") or {}).get("request"),
                                "gateway_token": (tr.get("step2") or {}).get("gateway_token_full"), "step2_request": (tr.get("step2") or {}).get("request"),
                                "web_identity": x.get("web_identity"), "aws_jwt": x.get("aws_jwt_full"), "openai_token": x.get("openai_token_full"),
                                "call": x.get("call"), "model": tr.get("model"), "person": {"login": uid}}
    yield from from_agent(code, out, ms)


def run_guard_team(body):
    """Ask for a model the person's Okta group isn't allowed (Cedar reads `groups` + the requested model)."""
    g = (cfg()[2].get("target") or {})
    group = f"wif-{person_team() or 'engineering'}"
    allowed = (g.get("group_models") or {}).get(group, [])
    model = body.get("model") or next((m for m in g.get("models", []) if m not in allowed), "gpt-5.6-terra")
    yield {"kind": "hop", "edge": "agent", "status": "sending"}
    code, out, ms = invoke_agent({"prompt": "Say hi.", "model": model})
    yield from from_agent(code, out, ms, label=f"{group} asks for {model}")


def run_guard_direct(_):
    """The person's own sign-in token, straight at the Gateway (not delegated, not via the agent)."""
    g = cfg()[2]
    yield {"kind": "hop", "edge": "direct", "status": "sending"}
    code, out = http(g["gw_url"].split("/mcp")[0] + "/inference/v1/chat/completions",
                     {"model": "openai/gpt-4.1-mini", "messages": [{"role": "user", "content": "hi"}]},
                     {"Authorization": f"Bearer {SESSION['access_token']}"}, timeout=60)
    yield {"kind": "hop", "edge": "direct", "status": code}
    c = claims_of(SESSION["access_token"])
    yield {"kind": "result", "data": {"ok": code == 200, "guard": "direct", "http": code, "response": out,
                                      "sent": {"to": "Gateway /inference/v1/chat/completions", "bearer": "the person's own sign-in token (not delegated)",
                                               "claims": {k: c.get(k) for k in ("iss", "aud", "cid", "sub", "scp")}}}}


def run_guard_forged(_):
    """An edited Okta token (signature changed) at AgentCore Runtime."""
    h, p, sig = SESSION["access_token"].split(".")
    forged = f"{h}.{p}.{sig[:-6]}{'AAAAAA' if sig[-6:] != 'AAAAAA' else 'BBBBBB'}"
    yield {"kind": "hop", "edge": "agent", "status": "sending"}
    code, out, ms = invoke_agent({"prompt": "hi"}, access_token=forged)
    yield {"kind": "hop", "edge": "agent", "status": code, "ms": ms}
    yield {"kind": "result", "data": {"ok": code == 200, "guard": "forged", "http": code, "response": out}}


def run_direct(body):
    yield {"kind": "hop", "edge": "agent", "status": "sending"}
    if body.get("bundle"):
        code, out, ms = invoke_direct({"prompt": body.get("prompt") or ""}, headers=bundle_headers(body["bundle"]))
    else:
        code, out, ms = invoke_direct({"prompt": body.get("prompt") or "", "model": body.get("model") or None})
    tr = out.get("trace", {}) if isinstance(out, dict) else {}
    yield {"kind": "hop", "edge": "agent", "status": 200 if code == 200 else code, "ms": ms}
    if tr.get("person"):
        p = tr["person"]
        yield {"kind": "hop", "edge": "webid", "status": "reused" if p.get("cached") else "ok", "ms": p.get("identity_ms"), "team": p.get("team")}
    elif isinstance(out, dict) and out.get("stage") == "web_identity":
        yield {"kind": "hop", "edge": "webid", "status": "denied"}
    if isinstance(out, dict) and (out.get("ok") or out.get("stage") == "model"):
        model_err = err_code(out.get("error")) if not out.get("ok") else None
        yield {"kind": "hop", "edge": "sts", "status": "ok" if tr.get("mints") else "reused", "ms": (tr.get("mints") or [{}])[0].get("ms")}
        yield {"kind": "hop", "edge": "exchange", "status": 200 if (out.get("ok") or model_err) else 401}
        if out.get("ok") or model_err:
            yield {"kind": "hop", "edge": "model", "status": model_err or 200, "ms": tr.get("model", {}).get("ms"), "model": tr.get("model", {}).get("model_id")}
    if isinstance(out, dict) and out.get("ok"):
        tr = out.get("trace") or {}
        SESSION["dchain"] = {"at": time.time(), "login": SESSION.get("login"), "id_token": decoded(SESSION["id_token"]), "access_token": decoded(SESSION["access_token"]),
                             "web_identity": (tr.get("person") or {}).get("web_identity"), "aws_jwt": tr.get("aws_jwt_full"),
                             "openai_token": tr.get("openai_token_full"), "model": tr.get("model"), "person": {"login": (tr.get("person") or {}).get("user")}}
    yield {"kind": "result", "data": {**(out if isinstance(out, dict) else {"ok": False, "error": out}), "http": code, "client_ms": ms}}


RUNS = {"direct": run_direct, "chat": run_chat, "guard_team": run_guard_team, "guard_direct": run_guard_direct, "guard_forged": run_guard_forged}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body, default=lambda o: sorted(o) if isinstance(o, set) else str(o)).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, url):
        self.send_response(302)
        self.send_header("Location", url)
        self.end_headers()

    def do_GET(self):
        path, _, query = self.path.partition("?")
        q = urllib.parse.parse_qs(query)
        ok = cfg()[0]
        if path == "/api/status":
            return self.send(200, status())
        if path == "/api/evidence":
            return self.send(200, evidence(float((q.get("since") or [time.time() - 1800])[0])))
        if path == "/api/claims":
            if not signed_in():
                return self.send(200, {})
            return self.send(200, {"id_token": claims_of(SESSION["id_token"]), "access_token": claims_of(SESSION["access_token"])})
        if path == "/api/chain":
            ok, aw, g = cfg()
            wid = json.loads((ROOT / "agent_state.json").read_text()).get("webid") or {}
            org = ok.get("users_issuer", "").split("/oauth2")[0]
            return self.send(200, {"chain": SESSION.get("dchain" if (q.get("p") or [""])[0] == "direct" else "chain"), "login": SESSION.get("login"), "ctx": {
                "agent": ok.get("client_id"), "kid": ok.get("kid"), "kms": ok.get("kms_key_arn"), "users_issuer": ok.get("users_issuer"), "org": org,
                "org_token_endpoint": f"{org}/oauth2/v1/token", "gateway_issuer": ok.get("gateway_issuer"), "gateway_token_endpoint": f"{ok.get('gateway_issuer')}/v1/token",
                "gateway_audience": ok.get("gateway_audience"), "gateway_scope": ok.get("gateway_scope"), "invoke_scope": ok.get("invoke_scope"),
                "webid": wid,
                "account": ACCT if "ACCT" in globals() else None, "openai": g.get("openai"), "group_models": (g.get("target") or {}).get("group_models")}})
        if path == "/api/last":
            return self.send(200, SESSION["last"] or {})
        if path == "/login":
            state, verifier = secrets.token_urlsafe(16), secrets.token_urlsafe(48)
            SESSION["pending"] = {state: verifier}
            return self.redirect(f"{ok['users_issuer']}/v1/authorize?" + urllib.parse.urlencode({
                "client_id": ok["client_id"], "response_type": "code", "scope": f"openid profile email {ok['invoke_scope']}",
                "redirect_uri": ok["redirect_uri"], "state": state, "prompt": "login",
                "code_challenge": b64u(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"}))
        if path == "/callback":
            verifier = SESSION["pending"].pop(q.get("state", [""])[0], None)
            if q.get("error") or not verifier:
                return self.send(400, f"Okta sign-in failed: {q.get('error', ['state mismatch'])[0]} {q.get('error_description', [''])[0]}".encode(), "text/plain")
            url = f"{ok['users_issuer']}/v1/token"
            ca = client_assertion(url)
            data = urllib.parse.urlencode({"grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": ok["redirect_uri"], "code_verifier": verifier,
                                           "client_id": ok["client_id"], "client_assertion_type": ASSERT, "client_assertion": ca}).encode()
            try:
                with _HTTPS.open(urllib.request.Request(url, data=data, method="POST", headers={
                        "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}), timeout=30) as r:
                    j = json.loads(r.read())
            except urllib.error.HTTPError as e:
                return self.send(400, f"Okta token request failed: {e.read().decode()[:400]}".encode(), "text/plain")
            SESSION.update(id_token=j["id_token"], access_token=j["access_token"], last=None, direct_sid=None, chain=None,
                           login={"assertion": decoded(ca), "token_endpoint": url, "response": {k: j.get(k) for k in ("token_type", "expires_in", "scope")},
                                  "request": {"grant_type": "authorization_code", "code": "<one-time code from /authorize>", "code_verifier": "<PKCE secret>",
                                              "redirect_uri": ok["redirect_uri"], "client_id": ok["client_id"], "client_assertion_type": ASSERT,
                                              "client_assertion": "<the KMS-signed JWT below>"},
                                  "authorize": {"client_id": ok["client_id"], "scope": f"openid profile email {ok['invoke_scope']}", "response_type": "code",
                                                "code_challenge_method": "S256", "prompt": "login"}})
            return self.redirect("/#live")
        if path == "/logout":
            tok = SESSION["id_token"]
            SESSION.update(id_token=None, access_token=None, last=None, direct_sid=None)
            if tok:
                return self.redirect(f"{ok['users_issuer']}/v1/logout?" + urllib.parse.urlencode({"id_token_hint": tok, "post_logout_redirect_uri": f"{BASE}/"}))
            return self.redirect("/")
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        f = (WEB / rel).resolve()
        if not str(f).startswith(str(WEB.resolve())) or not f.is_file():
            return self.send(404, {"error": "not found"})
        self.send(200, f.read_bytes(), {".html": "text/html; charset=utf-8", ".js": "text/javascript"}.get(f.suffix, "application/octet-stream"))

    def do_POST(self):
        key = self.path.rsplit("/", 1)[-1]
        if not self.path.startswith("/api/run/") or key not in RUNS:
            return self.send(404, {"error": "not found"})
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        except ValueError:
            body = {}
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        def emit(ev):
            self.wfile.write((json.dumps(ev, default=str) + "\n").encode())
            self.wfile.flush()
        try:
            if not signed_in():
                raise RuntimeError("Sign in with Okta first (top right)")
            for ev in RUNS[key](body):
                emit(ev)
        except Exception as e:
            emit({"kind": "error", "text": str(e)})
        emit({"kind": "done"})


if __name__ == "__main__":
    print(f"OpenAI WIF console · {BASE}")
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
