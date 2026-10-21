# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""AgentCore Observability for the Gateway: CloudWatch Transaction Search (account, one time) + Gateway logs and traces.

  Transaction Search   X-Ray may write spans to CloudWatch Logs (aws/spans), trace segments go there, 1% indexed (free tier)
  Gateway logs         APPLICATION_LOGS -> /aws/vendedlogs/bedrock-agentcore/gateway/APPLICATION_LOGS/<gateway id>
  Gateway traces       TRACES -> X-Ray -> aws/spans, shown in CloudWatch > GenAI Observability > Bedrock AgentCore > Gateways

Usage: python observability_setup.py up | status
"""
import json
import os
import sys
import time
from pathlib import Path

import boto3

ROOT = Path(__file__).parent
S = boto3.Session(profile_name=os.environ.get("AWS_PROFILE") or None, region_name=os.environ.get("AWS_REGION", "us-east-1"))
REG = S.region_name
logs, xray = S.client("logs"), S.client("xray")
ACCT = S.client("sts").get_caller_identity()["Account"]
TAGS = {"project": "openai-wif-demo"}


def gateway():
    g = json.loads((ROOT / "gateway" / "state.json").read_text())["gw"]
    return g, f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:gateway/{g}"


def transaction_search():
    logs.put_resource_policy(policyName="TransactionSearchXRayAccess", policyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{
            "Sid": "TransactionSearchXRayAccess", "Effect": "Allow", "Principal": {"Service": "xray.amazonaws.com"}, "Action": "logs:PutLogEvents",
            "Resource": [f"arn:aws:logs:{REG}:{ACCT}:log-group:aws/spans:*", f"arn:aws:logs:{REG}:{ACCT}:log-group:/aws/application-signals/data:*"],
            "Condition": {"ArnLike": {"aws:SourceArn": f"arn:aws:xray:{REG}:{ACCT}:*"}, "StringEquals": {"aws:SourceAccount": ACCT}}}]}))
    if xray.get_trace_segment_destination()["Destination"] != "CloudWatchLogs":
        xray.update_trace_segment_destination(Destination="CloudWatchLogs")
    for _ in range(60):   # the switch is asynchronous; X-Ray delivery needs it ACTIVE
        d = xray.get_trace_segment_destination()
        if d["Destination"] == "CloudWatchLogs" and d["Status"] == "ACTIVE":
            break
        time.sleep(10)
    else:
        raise SystemExit(f"trace segment destination still {d}")
    xray.update_indexing_rule(Name="Default", Rule={"Probabilistic": {"DesiredSamplingPercentage": 1.0}})
    print("Transaction Search: spans -> CloudWatch Logs (aws/spans), 1% indexed")


def gateway_delivery():
    gid, arn = gateway()
    group = f"/aws/vendedlogs/bedrock-agentcore/gateway/APPLICATION_LOGS/{gid}"
    try:
        logs.create_log_group(logGroupName=group, tags=TAGS)
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    have = {d["name"] for d in logs.describe_delivery_sources()["deliverySources"]}
    for kind in ("APPLICATION_LOGS", "TRACES"):
        name = f"{gid}-{'logs' if kind == 'APPLICATION_LOGS' else 'traces'}"
        if name not in have:
            logs.put_delivery_source(name=name, logType=kind, resourceArn=arn, tags=TAGS)
        dest = next((d for d in logs.describe_delivery_destinations()["deliveryDestinations"] if d["name"] == name + "-dest"), None) or logs.put_delivery_destination(
            name=name + "-dest", tags=TAGS,
            **({"deliveryDestinationConfiguration": {"destinationResourceArn": f"arn:aws:logs:{REG}:{ACCT}:log-group:{group}"}}
               if kind == "APPLICATION_LOGS" else {"deliveryDestinationType": "XRAY"}))["deliveryDestination"]
        done = {(d["deliverySourceName"], d["deliveryDestinationArn"]) for d in logs.describe_deliveries()["deliveries"]}
        if (name, dest["arn"]) not in done:
            logs.create_delivery(deliverySourceName=name, deliveryDestinationArn=dest["arn"], tags=TAGS)
        print(f"Gateway {gid}: {kind} -> {group if kind == 'APPLICATION_LOGS' else 'X-Ray (aws/spans)'}")


def status():
    print("trace destination:", xray.get_trace_segment_destination())
    gid, _ = gateway()
    for d in logs.describe_deliveries()["deliveries"]:
        if d["deliverySourceName"].startswith(gid):
            print("delivery:", d["deliverySourceName"], "->", d["deliveryDestinationType"])


if __name__ == "__main__":
    if os.environ.get("AWS_ACCOUNT_ID", ACCT) != ACCT:   # optional guard: AWS_ACCOUNT_ID in config.env
        sys.exit(f"your AWS profile is account {ACCT}, but config.env says AWS_ACCOUNT_ID={os.environ['AWS_ACCOUNT_ID']}")
    if sys.argv[1] == "up":
        transaction_search()
        gateway_delivery()
    status()
