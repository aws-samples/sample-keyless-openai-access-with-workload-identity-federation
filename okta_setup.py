# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Create the Okta side of the demo (needs OKTA_DOMAIN and OKTA_API_TOKEN in config.env).

Everything is new and prefixed wif-; existing apps and servers are not touched.

  wif-engineering / wif-finance   groups. Group = team. The team travels Okta -> AWS -> OpenAI.
  wif-openai-users                custom authorization server. Its ID tokens carry, in the
                                  names AWS STS reads for AssumeRoleWithWebIdentity:
                                    https://aws.amazon.com/source_identity              = login
                                    https://aws.amazon.com/tags/principal_tags/team     = team
Run it before okta_agent_setup.py, which creates the agent, its own sign-in app and the access policy.
Safe to re-run: each object is looked up by name first.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

# HTTPS only: urllib.request.urlopen would also open file:// and other schemes
_HTTPS = urllib.request.OpenerDirector()
for _h in (urllib.request.ProxyHandler(), urllib.request.HTTPSHandler(), urllib.request.HTTPRedirectHandler(),
           urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor(), urllib.request.UnknownHandler()):
    _HTTPS.add_handler(_h)

DOMAIN = os.environ.get("OKTA_DOMAIN", "").rstrip("/")
TOKEN = os.environ.get("OKTA_API_TOKEN", "")
if not (DOMAIN and TOKEN):
    sys.exit("Set OKTA_DOMAIN and OKTA_API_TOKEN in config.env (Okta admin > Security > API > Tokens).")
TEAMS = {"engineering": os.environ.get("OKTA_ENGINEERING_USERS", "ada.lovelace@example.com"),
         "finance": os.environ.get("OKTA_FINANCE_USERS", "grace.hopper@example.com")}
TEAM_EXPR = ('isMemberOfGroupName("wif-finance") ? "finance" : '
             '(isMemberOfGroupName("wif-engineering") ? "engineering" : null)')


def call(method, path, body=None, params=None):
    url = DOMAIN + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"SSWS {TOKEN}", "Accept": "application/json", "Content-Type": "application/json"})
    try:
        with _HTTPS.open(req, timeout=30) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path} -> {e.code}: {e.read().decode()[:600]}") from None


def find(path, name, key="name", params=None):
    for item in call("GET", path, params=params):
        val = item.get("profile", {}).get("name") if key == "profile.name" else item.get(key)
        if val == name:
            return item
    return None


def user_id(login):
    users = call("GET", "/api/v1/users", params={"search": f'profile.login eq "{login}"'})
    if not users:
        raise RuntimeError(f"Okta user {login} not found: create it, or set OKTA_*_USERS in config.env")
    return users[0]["id"]


def group(name, description):
    g = find("/api/v1/groups", name, key="profile.name", params={"q": name})
    return (g or call("POST", "/api/v1/groups", {"profile": {"name": name, "description": description}}))["id"]


def claim(asid, name, value, value_type="EXPRESSION", **extra):
    body = {"name": name, "status": "ACTIVE", "claimType": "IDENTITY", "valueType": value_type, "value": value,
            "alwaysIncludeInToken": True, "conditions": {"scopes": ["openid"]}, **extra}
    existing = find(f"/api/v1/authorizationServers/{asid}/claims", name)
    if existing:
        call("PUT", f"/api/v1/authorizationServers/{asid}/claims/{existing['id']}", body)
    else:
        call("POST", f"/api/v1/authorizationServers/{asid}/claims", body)


def main():
    gids = {t: group(f"wif-{t}", f"OpenAI WIF demo: {t} team") for t in TEAMS}
    for team, logins in TEAMS.items():
        for login in filter(None, (s.strip() for s in logins.split(","))):
            call("PUT", f"/api/v1/groups/{gids[team]}/users/{user_id(login)}")

    aserver = find("/api/v1/authorizationServers", "wif-openai-users") or call("POST", "/api/v1/authorizationServers", {
        "name": "wif-openai-users", "description": "OpenAI WIF demo: sign-in whose ID token AWS STS trusts",
        "audiences": ["openai-wif-demo"]})
    asid = aserver["id"]
    claim(asid, "https://aws.amazon.com/source_identity", "user.login")
    claim(asid, "https://aws.amazon.com/tags/principal_tags/team", TEAM_EXPR)
    claim(asid, "groups", "wif-", value_type="GROUPS", group_filter_type="STARTS_WITH")

    print(f"  issuer     {aserver['issuer']}\n  teams      " + ", ".join(f"wif-{t}: {TEAMS[t]}" for t in TEAMS))

if __name__ == "__main__":
    main()
