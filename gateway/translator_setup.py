# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""One IAM -> OpenAI translator for every team (replaces one-per-team). Idempotent.

  OpenAIWifTranslatorRole   the Lambda's role: logs only. It needs no AWS permission to act for a person: the
                            person's Okta token is the credential (AssumeRoleWithWebIdentity)
  team roles                OpenAIWifGateway<Team>Role: trusted only by the Okta OIDC providers (webid_setup.py),
                            for that team's tag; may only mint OpenAI-audience AWS tokens
Run after webid_setup.py up.
  openai-wif-translator     Lambda Function URL (AWS_IAM)
  Gateway target            openai -> <translator URL>, outbound GATEWAY_IAM_ROLE (SigV4, lambda)

Usage: python translator_setup.py up | down
"""
import io
import json
import os
import sys
import time
import zipfile
from pathlib import Path

import boto3

sys.path.insert(0, str(Path(__file__).parent.parent))

HERE = Path(__file__).parent
S = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None, region_name=os.environ.get("AWS_REGION", "us-east-1"))
iam, lam, ac, sts = S.client("iam"), S.client("lambda"), S.client("bedrock-agentcore-control"), S.client("sts")
ACCT = sts.get_caller_identity()["Account"]
STATE = HERE / "state.json"
FN, ROLE, GW_ROLE = "openai-wif-translator", "OpenAIWifTranslatorRole", "OpenAIWifGatewayServiceRole"
PROVIDER_ID = os.environ.get("OPENAI_IDENTITY_PROVIDER_ID", "")   # config.env
TAGS = {"project": "openai-wif-demo"}
MODEL = "gpt-4.1-mini"


def team_role(team):
    return f"arn:aws:iam::{ACCT}:role/OpenAIWifGateway{team.title()}Role"


def up():
    st = json.loads(STATE.read_text())
    teams = st["teams"]

    # 1. translator role: logs only
    trust = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
    try:
        trole = iam.create_role(RoleName=ROLE, AssumeRolePolicyDocument=trust, Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()],
                                Description="OpenAI WIF translator: logs only; acts for a person with their Okta token (web identity)")["Role"]["Arn"]
        time.sleep(12)
    except iam.exceptions.EntityAlreadyExistsException:
        trole = iam.get_role(RoleName=ROLE)["Role"]["Arn"]
    iam.put_role_policy(RoleName=ROLE, PolicyName="openai-wif", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": [f"arn:aws:logs:{S.region_name}:{ACCT}:log-group:/aws/lambda/{FN}", f"arn:aws:logs:{S.region_name}:{ACCT}:log-group:/aws/lambda/{FN}:*"]}]}))
    print("translator role", trole)

    # 2. team roles: trust comes from webid_setup.py (Okta OIDC providers only); permissions: mint OpenAI tokens only
    for t in teams:
        name = team_role(t).split("/")[-1]
        iam.put_role_policy(RoleName=name, PolicyName="openai-wif", PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "sts:GetWebIdentityToken", "Resource": "*",
             "Condition": {"ForAllValues:StringEquals": {"sts:IdentityTokenAudience": "https://api.openai.com/v1"},
                           "NumericLessThanEquals": {"sts:DurationSeconds": 3600}}}]}))

    # 3. the one translator
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("translator.py", (HERE / "translator.py").read_bytes())
    from gateway_obo import MODELS
    env = {"Variables": {"OPENAI_IDENTITY_PROVIDER_ID": PROVIDER_ID, "TEAM_ROLES": json.dumps({t: team_role(t) for t in teams}),
                         "SERVICE_ACCOUNTS": json.dumps({t: v["sa"] for t, v in teams.items()}), "MODELS": json.dumps(MODELS)}}
    for attempt in range(6):
        try:
            fn = lam.create_function(FunctionName=FN, Runtime="python3.13", Role=trole, Handler="translator.handler", Code={"ZipFile": buf.getvalue()},
                                     Timeout=60, MemorySize=256, Environment=env, Tags=TAGS,
                                     Description="IAM -> short-lived OpenAI token, per team (path /<team>/...)")["FunctionArn"]
            break
        except lam.exceptions.ResourceConflictException:
            fn = lam.update_function_code(FunctionName=FN, ZipFile=buf.getvalue())["FunctionArn"]
            lam.get_waiter("function_updated_v2").wait(FunctionName=FN)
            lam.update_function_configuration(FunctionName=FN, Environment=env)
            break
        except lam.exceptions.InvalidParameterValueException:
            time.sleep(8)
    lam.get_waiter("function_active_v2").wait(FunctionName=FN)
    try:
        url = lam.create_function_url_config(FunctionName=FN, AuthType="AWS_IAM")["FunctionUrl"].rstrip("/")
    except lam.exceptions.ResourceConflictException:
        url = lam.get_function_url_config(FunctionName=FN)["FunctionUrl"].rstrip("/")
    print("translator", url)

    # 4. gateway role: may call the one translator (keep the interceptor + policy statements)
    pol = iam.get_role_policy(RoleName=GW_ROLE, PolicyName="openai-wif")["PolicyDocument"]
    pol["Statement"] = [s for s in pol["Statement"] if s.get("Sid") in ("Interceptor", "Policy")] + [
        {"Sid": "Translator", "Effect": "Allow", "Action": ["lambda:InvokeFunctionUrl", "lambda:InvokeFunction"], "Resource": fn}]
    iam.put_role_policy(RoleName=GW_ROLE, PolicyName="openai-wif", PolicyDocument=json.dumps(pol))
    time.sleep(10)

    # 5. the Gateway's one inference target `openai` -> the translator root (gateway_obo.one_target)
    st.update(translator={"fn": fn, "url": url, "role": trole})
    STATE.write_text(json.dumps(st, indent=1))
    old_fns = {t: v.get("fn") for t, v in teams.items() if v.get("fn") and not v["fn"].endswith(f":{FN}")}
    from gateway_obo import one_target
    one_target(st)
    st.update(translator={"fn": fn, "url": url, "role": trole})
    STATE.write_text(json.dumps(st, indent=1))

    # 6. retire the per-team translators
    for t, old in old_fns.items():
        name = old.split(":")[-1]
        for f in (lambda: lam.delete_function(FunctionName=name), lambda: S.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")):
            try:
                f()
            except Exception:
                pass
        print("retired", name)


def down():
    for f in (lambda: lam.delete_function(FunctionName=FN), lambda: S.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{FN}"),
              lambda: (iam.delete_role_policy(RoleName=ROLE, PolicyName="openai-wif"), iam.delete_role(RoleName=ROLE))):
        try:
            f()
        except Exception:
            pass
    print("translator removed")


if __name__ == "__main__":
    if os.environ.get("AWS_ACCOUNT_ID", ACCT) != ACCT:   # optional guard: AWS_ACCOUNT_ID in config.env
        sys.exit(f"your AWS profile is account {ACCT}, but config.env says AWS_ACCOUNT_ID={os.environ['AWS_ACCOUNT_ID']}")
    {"up": up, "down": down}[sys.argv[1]]()
