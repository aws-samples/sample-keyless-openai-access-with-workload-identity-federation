# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Test helper (no browser): sign a demo user in to the agent's own Okta app, then run the two
Cross App Access steps directly against Okta, signing client assertions with the agent's KMS key.
Prints decoded claims only. Saves tokens (git-ignored) for gateway tests.
Usage: python scripts/okta_chain_test.py ada.lovelace@example.com"""
import base64, hashlib, json, os, secrets, sys, time, uuid, urllib.parse
from pathlib import Path
import boto3, requests

ROOT = Path(__file__).resolve().parents[1]
st = json.loads((ROOT / "agent_state.json").read_text())["okta"]
DOMAIN = os.environ["OKTA_DOMAIN"].rstrip("/")
PASSWORD = os.environ["DEMO_USER_PASSWORD"]   # the demo user's Okta password, from your shell (never stored here)
kms = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None, region_name=os.environ.get("AWS_REGION", "us-east-1")).client("kms")
b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
ASSERT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def assertion(aud):
    now = int(time.time())
    si = f"{b64(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': st['kid']}).encode())}." \
         f"{b64(json.dumps({'iss': st['client_id'], 'sub': st['client_id'], 'aud': aud, 'iat': now, 'exp': now + 300, 'jti': str(uuid.uuid4())}).encode())}"
    sig = kms.sign(KeyId=st["kms_key_arn"], Message=hashlib.sha256(si.encode()).digest(), MessageType="DIGEST", SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256")["Signature"]
    return f"{si}.{b64(sig)}"


def claims(t):
    p = t.split(".")[1]; return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def post(url, data, what):
    r = requests.post(url, data=data, timeout=30)
    if r.status_code >= 400:
        sys.exit(f"{what}: HTTP {r.status_code} {r.text[:400]}")
    return r.json()


user = sys.argv[1]
s = requests.post(f"{DOMAIN}/api/v1/authn", json={"username": user, "password": PASSWORD}, timeout=30).json()
if "sessionToken" not in s:
    sys.exit(f"authn: {json.dumps(s)[:300]}")
ver = secrets.token_urlsafe(48); ch = b64(hashlib.sha256(ver.encode()).digest())
a = requests.get(f"{st['users_issuer']}/v1/authorize", allow_redirects=False, timeout=30, params={
    "client_id": st["client_id"], "response_type": "code", "scope": f"openid profile email {st['invoke_scope']}", "redirect_uri": st["redirect_uri"],
    "state": "x", "code_challenge": ch, "code_challenge_method": "S256", "sessionToken": s["sessionToken"]})
qs = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(a.headers.get("Location", "")).query))
if "code" not in qs:
    sys.exit(f"authorize: {a.status_code} {qs or a.text[:300]}")
url = f"{st['users_issuer']}/v1/token"
t = post(url, {"grant_type": "authorization_code", "code": qs["code"], "redirect_uri": st["redirect_uri"], "code_verifier": ver,
               "client_id": st["client_id"], "client_assertion_type": ASSERT, "client_assertion": assertion(url)}, "sign-in token")
pick = lambda c, ks: {k: c.get(k) for k in ks if k in c}
print("1 sign-in  id_token :", json.dumps(pick(claims(t["id_token"]), ("iss", "aud", "sub", "preferred_username"))))
print("           access   :", json.dumps(pick(claims(t["access_token"]), ("aud", "cid", "uid", "scp"))))
org = f"{DOMAIN}/oauth2/v1/token"
jag = post(org, {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                 "subject_token": t["id_token"], "subject_token_type": "urn:ietf:params:oauth:token-type:id_token",
                 "audience": st["gateway_issuer"], "scope": st["gateway_scope"], "client_assertion_type": ASSERT, "client_assertion": assertion(org)}, "step 1 (ID-JAG)")["access_token"]
print("2 ID-JAG            :", json.dumps(pick(claims(jag), ("iss", "aud", "sub", "client_id", "act", "scope"))))
gurl = f"{st['gateway_issuer']}/v1/token"
gw = post(gurl, {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jag, "client_assertion_type": ASSERT,
                 "client_assertion": assertion(gurl)}, "step 2 (gateway token)")["access_token"]
print("3 gateway token     :", json.dumps(pick(claims(gw), ("iss", "aud", "sub", "uid", "cid", "act", "scp", "team", "groups", "login", "exp"))))
(ROOT / "build").mkdir(exist_ok=True)
(ROOT / "build" / f".chain_{user.split('@')[0]}.json").write_text(json.dumps({"id_token": t["id_token"], "access_token": t["access_token"], "gateway_token": gw}))
