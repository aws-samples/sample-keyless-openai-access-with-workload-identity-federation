#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
# Start the console on http://localhost:8090 (local only). Uses your AWS profile (AWS_PROFILE in config.env) to
# sign as the agent with KMS and read status/usage; it never talks to OpenAI itself.
set -euo pipefail
cd "$(dirname "$0")"
[ -f config.env ] || cp config.env.example config.env
set -a; source config.env; set +a
export AWS_DEFAULT_REGION="$AWS_REGION"
[ -d .venv ] || { uv venv -q --python 3.12 .venv && uv pip install -q --python .venv/bin/python -r console/requirements.txt; }
( sleep 1; open "http://localhost:8090" ) &
exec .venv/bin/python -u console/server.py
