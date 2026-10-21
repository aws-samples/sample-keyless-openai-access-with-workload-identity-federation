# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AgentCore configuration bundles: one per model, each pinning model_id for BOTH agents. Idempotent.

  wif_model_terra · wif_model_luna · wif_model_sol
    components: { <Gateway agent runtime ARN>: {configuration: {model_id}}, <Direct agent runtime ARN>: {...} }
  The console picks a bundle per question and passes it on the invoke as W3C baggage
  (aws.agentcore.configbundle_arn / _version). The agents read it with BedrockAgentCoreContext.get_config_bundle():
  the model comes from the bundle, not from the agent's code. Cedar and OpenAI's project limit still decide.

Usage: python bundles_setup.py up | down

Scope: the GPT-5.6 models used here (Sol, Terra, Luna) are also generally available on Amazon Bedrock, where IAM, CloudWatch and Cost Explorer cover them natively; that is the simpler path for most workloads. This demo is for when you need OpenAI's own API (an existing OpenAI organization, projects and limits) without API keys.
"""
import json
import os
import sys
import uuid
from pathlib import Path

import boto3

ROOT = Path(__file__).parent
S = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None, region_name=os.environ.get("AWS_REGION", "us-east-1"))
ac = S.client("bedrock-agentcore-control")
MODELS = ["gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.6-sol"]
STATE = ROOT / "agent_state.json"


def up():
    st = json.loads(STATE.read_text())
    arns = [st["aws"]["runtime_arn"], st["direct"]["runtime_arn"]]
    have = {b["bundleName"]: b for b in ac.list_configuration_bundles().get("bundles", [])}
    out = {}
    for m in MODELS:
        name = "wif_model_" + m.split("-")[-1]
        comps = {a: {"configuration": {"model_id": m}} for a in arns}
        if name in have:
            b = ac.get_configuration_bundle(bundleId=have[name]["bundleId"])
            arn, bid, ver = b["bundleArn"], b["bundleId"], b.get("versionId") or b.get("latestVersionId")
            cur = (b.get("components") or {})
            if {k: v.get("configuration") for k, v in cur.items()} != {k: v["configuration"] for k, v in comps.items()}:
                u = ac.update_configuration_bundle(bundleId=bid, components=comps, commitMessage=f"pin {m} for both agents", clientToken=str(uuid.uuid4()))
                ver = u.get("versionId", ver)
        else:
            r = ac.create_configuration_bundle(bundleName=name, components=comps, description=f"OpenAI WIF demo: the agent uses {m}",
                                               branchName="mainline", commitMessage=f"pin {m} for both agents", clientToken=str(uuid.uuid4()),
                                               tags={"project": "openai-wif-demo"})
            arn, bid, ver = r["bundleArn"], r["bundleId"], r["versionId"]
        out[m] = {"name": name, "id": bid, "arn": arn, "version": ver}
        print(f"{name}: {m} · {bid} · version {ver}")
    st["bundles"] = out
    STATE.write_text(json.dumps(st, indent=1))


def down():
    st = json.loads(STATE.read_text())
    for m, b in (st.get("bundles") or {}).items():
        try:
            ac.delete_configuration_bundle(bundleId=b["id"]); print("deleted", b["name"])
        except Exception as e:
            print(b["name"], str(e)[:120])


if __name__ == "__main__":
    {"up": up, "down": down}[sys.argv[1]]()
