# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Option C: the Okta token itself becomes the AWS credential (IAM web identity federation). Idempotent.

  Okta claims      both servers put, in their ACCESS tokens, the names STS reads for AssumeRoleWithWebIdentity:
                     https://aws.amazon.com/source_identity          = login   (the person, kept for the whole session)
                     https://aws.amazon.com/tags/principal_tags/team = team    (from the wif-* group)
                     https://aws.amazon.com/tags/principal_tags/user = login
  IAM OIDC         one provider per Okta server: wif-gateway (client openai-wif-gateway, the translator's token)
                   and the sign-in server (client openai-wif-demo added, the Direct agent's token)
  Team roles       trust the providers, not any AWS principal. IAM is the mapping: a role admits a token only if its
                   team tag is that role's team, with only the team/user tag keys, and a source identity set.

Usage: python webid_setup.py up [--keep-old]   (--keep-old keeps the earlier AssumeRole trust statements)
       python webid_setup.py test ada|grace
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

import boto3

# HTTPS only: urllib.request.urlopen would also open file:// and other schemes
_HTTPS = urllib.request.OpenerDirector()
for _h in (urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPRedirectHandler(),
           urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(), urllib.request.UnknownHandler()):
    _HTTPS.add_handler(_h)

ROOT = Path(__file__).parent
S = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None, region_name=os.environ.get("AWS_REGION", "us-east-1"))
iam, sts = S.client("iam"), S.client("sts")
ACCT = sts.get_caller_identity()["Account"]
TEAMS = {"engineering": "OpenAIWifGatewayEngineeringRole", "finance": "OpenAIWifGatewayFinanceRole"}
TAG = "https://aws.amazon.com/tags/principal_tags/"
SRC = "https://aws.amazon.com/source_identity"
TAGS = [{"Key": "project", "Value": "openai-wif-demo"}]


def okta():
    return json.loads((ROOT / "agent_state.json").read_text())["okta"]


def okta_call(method, path, body=None):
    d, t = os.environ["OKTA_DOMAIN"].rstrip("/"), os.environ["OKTA_API_TOKEN"]
    req = urllib.request.Request(d + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"SSWS {t}", "Accept": "application/json", "Content-Type": "application/json"})
    with _HTTPS.open(req, timeout=30) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def access_claims(asid):
    """Add the STS claim names to the server's access tokens (RESOURCE claims). Leaves id_token claims alone."""
    have = {(c["name"], c["claimType"]): c for c in okta_call("GET", f"/api/v1/authorizationServers/{asid}/claims")}
    team_expr = next(c["value"] for (n, t), c in have.items() if n in ("team", TAG + "team"))
    want = {SRC: "user.login", TAG + "team": team_expr, TAG + "user": "user.login"}
    for name, value in want.items():
        body = {"name": name, "status": "ACTIVE", "claimType": "RESOURCE", "valueType": "EXPRESSION", "value": value,
                "alwaysIncludeInToken": True, "conditions": {"scopes": []}}
        ex = have.get((name, "RESOURCE"))
        if ex:
            okta_call("PUT", f"/api/v1/authorizationServers/{asid}/claims/{ex['id']}", body)
        else:
            okta_call("POST", f"/api/v1/authorizationServers/{asid}/claims", body)
    print(f"Okta {asid}: access-token claims {list(want)}")


def provider(issuer, client_id):
    url = issuer.replace("https://", "")
    arn = f"arn:aws:iam::{ACCT}:oidc-provider/{url}"
    try:
        p = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
        if client_id not in p["ClientIDList"]:
            iam.add_client_id_to_open_id_connect_provider(OpenIDConnectProviderArn=arn, ClientID=client_id)
    except iam.exceptions.NoSuchEntityException:
        thumbs = next((iam.get_open_id_connect_provider(OpenIDConnectProviderArn=a["Arn"])["ThumbprintList"]
                       for a in iam.list_open_id_connect_providers()["OpenIDConnectProviderList"] if url.split("/")[0] in a["Arn"]), [])
        iam.create_open_id_connect_provider(Url=issuer, ClientIDList=[client_id], ThumbprintList=thumbs, Tags=TAGS)
    print(f"IAM OIDC provider {url} · client {client_id}")
    return arn, url


def trust(team, providers, keep_old):
    """Each provider: AssumeRoleWithWebIdentity + TagSession only for this role's team; SetSourceIdentity required."""
    stmts = []
    for i, (arn, url, aud) in enumerate(providers):
        stmts += [
            {"Sid": f"WebIdentity{i}", "Effect": "Allow", "Principal": {"Federated": arn},
             "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
             "Condition": {"StringEquals": {f"{url}:aud": aud, "aws:RequestTag/team": team},
                           "ForAllValues:StringEquals": {"aws:TagKeys": ["team", "user"]}}},
            {"Sid": f"SourceIdentity{i}", "Effect": "Allow", "Principal": {"Federated": arn}, "Action": "sts:SetSourceIdentity",
             "Condition": {"StringEquals": {f"{url}:aud": aud}, "StringLike": {"sts:SourceIdentity": "*"}}}]
    if keep_old:
        cur = iam.get_role(RoleName=TEAMS[team])["Role"]["AssumeRolePolicyDocument"]["Statement"]
        stmts = [s for s in cur if not str(s.get("Sid", "")).startswith(("WebIdentity", "SourceIdentity"))] + stmts
    iam.update_assume_role_policy(RoleName=TEAMS[team], PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": stmts}))
    print(f"{TEAMS[team]} trust: web identity for team={team}" + (" (+ earlier AssumeRole statements kept)" if keep_old else " only"))


def up(keep_old):
    ok = okta()
    for iss in (ok["gateway_issuer"], ok["users_issuer"]):
        access_claims(iss.rstrip("/").split("/")[-1])
    gw = provider(ok["gateway_issuer"], ok["gateway_audience"])
    si = provider(ok["users_issuer"], "openai-wif-demo")
    for team in TEAMS:
        trust(team, [(*gw, ok["gateway_audience"]), (*si, "openai-wif-demo")], keep_old)
    s = json.loads((ROOT / "agent_state.json").read_text())
    s["webid"] = {"gateway_provider": gw[0], "signin_provider": si[0], "roles": {t: f"arn:aws:iam::{ACCT}:role/{r}" for t, r in TEAMS.items()}}
    (ROOT / "agent_state.json").write_text(json.dumps(s, indent=1))


def claims(tok):
    p = tok.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def test(who):
    """With fresh tokens from scripts/okta_chain_test.py: own team's role allowed, other team's refused, JWT contents, OpenAI exchange."""
    t = json.loads((ROOT / "build" / f".chain_{'ada.lovelace' if who == 'ada' else 'grace.hopper'}.json").read_text())
    gw_state = json.loads((ROOT / "gateway" / "state.json").read_text())
    anon = boto3.client("sts", region_name=S.region_name, endpoint_url=f"https://sts.{S.region_name}.amazonaws.com",
                        config=__import__("botocore.config", fromlist=["Config"]).Config(signature_version=__import__("botocore").UNSIGNED))
    for label, tok in (("Gateway token (translator)", t["gateway_token"]), ("sign-in access token (Direct agent)", t["access_token"])):
        c = claims(tok)
        team = c.get(TAG + "team")
        print(f"== {who} · {label}: team tag {team!r}, user tag {c.get(TAG + 'user')!r}, source_identity {c.get(SRC)!r}")
        for t2, role in TEAMS.items():
            try:
                r = anon.assume_role_with_web_identity(RoleArn=f"arn:aws:iam::{ACCT}:role/{role}", RoleSessionName=f"person-{who}", WebIdentityToken=tok, DurationSeconds=3600)
                print(f"   {role}: ALLOWED · source identity {r.get('SourceIdentity')} · subject {r.get('SubjectFromWebIdentityToken')}")
                if t2 != team:
                    continue
                cr = r["Credentials"]
                s2 = boto3.client("sts", region_name=S.region_name, endpoint_url=f"https://sts.{S.region_name}.amazonaws.com", aws_access_key_id=cr["AccessKeyId"],
                                  aws_secret_access_key=cr["SecretAccessKey"], aws_session_token=cr["SessionToken"])
                jwt = s2.get_web_identity_token(Audience=["https://api.openai.com/v1"], SigningAlgorithm="ES384", DurationSeconds=900)["WebIdentityToken"]
                jc = claims(jwt)
                print("   AWS JWT sub:", jc["sub"])
                print("   AWS JWT sts ns:", json.dumps(jc.get("https://sts.amazonaws.com/"))[:500])
                body = json.dumps({"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
                                   "subject_token": jwt, "identity_provider_id": os.environ["OPENAI_IDENTITY_PROVIDER_ID"], "service_account_id": gw_state["teams"][team]["sa"]}).encode()
                try:
                    with _HTTPS.open(urllib.request.Request("https://auth.openai.com/oauth/token", data=body, headers={"Content-Type": "application/json"}), timeout=20) as x:
                        print("   OpenAI exchange: HTTP", x.status)
                except urllib.error.HTTPError as e:
                    print("   OpenAI exchange: HTTP", e.code, e.read()[:200])
            except Exception as e:
                print(f"   {role}: REFUSED · {type(e).__name__}: {str(e)[:140]}")


if __name__ == "__main__":
    if os.environ.get("AWS_ACCOUNT_ID", ACCT) != ACCT:   # optional guard: AWS_ACCOUNT_ID in config.env
        sys.exit(f"your AWS profile is account {ACCT}, but config.env says AWS_ACCOUNT_ID={os.environ['AWS_ACCOUNT_ID']}")
    if sys.argv[1] == "up":
        up("--keep-old" in sys.argv)
    else:
        test(sys.argv[2] if len(sys.argv) > 2 else "ada")
