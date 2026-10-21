# Okta → AgentCore → OpenAI, with no keys

A person signs in with Okta. A **Strands agent on AgentCore Runtime** acts for them through Okta Cross App Access (OBO delegation), and calls OpenAI models through **AgentCore Gateway**. The Gateway reaches OpenAI with **IAM**. Only at the last hop does a small translator swap IAM for a **short-lived OpenAI token**. It hands the person's own Okta token to STS as a **web identity** (`AssumeRoleWithWebIdentity`, IAM OIDC provider = Okta). **IAM is the mapping:** each team role's trust policy admits the token only if its `team` tag (from the Okta group) is that role's team. The session carries the person (source identity = their login), and the AWS JWT it mints is exchanged via OpenAI Workload Identity Federation (WIF). The agent's own role never gets an OpenAI token. Nothing in the chain stores an OpenAI API key or an Okta client secret.

> Scope: the GPT-5.6 models used here (Sol, Terra, Luna) are also generally available on Amazon Bedrock, where IAM, CloudWatch and Cost Explorer cover them natively; that is the simpler path for most workloads. This demo is for when you need OpenAI's own API (an existing OpenAI organization, projects and limits) without API keys. See [GPT-5.6 on Amazon Bedrock](https://aws.amazon.com/about-aws/whats-new/2026/07/openai-gpt-sol-terra/).

```
Ada ─sign in─▶ Okta (the AI agent's own app; agent authenticates with a KMS key)
  └▶ Agent · AgentCore Runtime (admits only tokens issued to the agent)
       @requires_access_token × 2 via AgentCore Identity (KMS-signed):
         id_token ─▶ ID-JAG ─▶ Gateway token  { sub: Ada, act: agent, groups: [wif-engineering],
                                               source_identity + tags/team + tags/user (the names STS reads) }
  └▶ AgentCore Gateway /inference   Okta JWT in · ONE target `openai` · Cedar: your Okta `groups` claim → your models
       target allowlists ONE header, X-Person-Token (header propagation, no interceptor Lambda)
       ─SigV4 (GATEWAY_IAM_ROLE) + X-Person-Token─▶ one translator (Lambda URL, IAM only)
            sts:AssumeRoleWithWebIdentity(OpenAIWifGatewayEngineeringRole, WebIdentityToken = Ada's Gateway token)
              trust: Okta OIDC provider · aud = openai-wif-gateway · aws:RequestTag/team = "engineering"
            sts:GetWebIdentityToken → { sub: team role, source_identity: Ada, principal_tags: {team, user: Ada} }
            → OpenAI token exchange
       ─short-lived Bearer─▶ OpenAI · Engineering service account · gpt-5.6-sol
```

| Who sees what | |
|---|---|
| **OpenAI** | the AWS JWT: `sub` = the team role (mapped to the team's service account), `source_identity` + `principal_tags.user` = the person. OpenAI's own token names the team service account |
| **Gateway** | the **person** and the **agent** (`sub`, `act`, `groups`). Cedar: `wif-engineering` → gpt-5.6-sol, gpt-5.6-luna · `wif-finance` → gpt-5.6-terra, gpt-5.6-luna (`context.input.model`) |
| **IAM** | the team role's trust policy decides who may become which team: only the Okta OIDC providers, only that team's tag, only the `team`/`user` tag keys, source identity required |
| **CloudTrail** | `AssumeRoleWithWebIdentity` → `responseElements.sourceIdentity` = the person; `GetWebIdentityToken` → `userIdentity.sessionContext.sourceIdentity` = the person (both patterns) |
| **Translator log** (CloudWatch) | `web_identity` (the session) and `aws_jwt_minted` lines: `sub`, `source_identity`, `jti`, lifetime (no token values) |

## The console (`./run.sh` → http://localhost:8090)

Screens:
- **Deploy:** live status of the five pieces (Okta, Runtime, Gateway, IAM web identity, OpenAI), plus the commands.
- **Navigation:** click the **WIF** badge (Workload Identity Federation) for the screen menu.
- **1 · How it works (UML):** the 20-step chain, the guardrails and the Direct pattern. Step through with ← and →; every message shows this deployment's real values.
- **2 · Architecture:** click a block for its key points.
- **3 · Live:** sign in as `ada.lovelace@example.com` (engineering) or `grace.hopper@example.com` (finance) and ask the agent. Click any block in the identity flow for what came in and went out on that run. The **Evidence** panel reads the translator log (seconds) and CloudTrail (usually within 1–5 minutes) and names the person each OpenAI token was minted for, with links to the CloudTrail events.
  - Pick a model in the person card: green = your group may use it, ✕ = Cedar will refuse it.
  - Guardrails: a model your group can't use → **403 Cedar** · your own token without the agent → **403 Gateway** · forged Okta token → **401 Runtime**.

## Prerequisites

- **AWS:** an account and Region with Amazon Bedrock AgentCore (Runtime, Gateway, Identity), a profile that can create IAM roles, Lambda functions, KMS keys and AgentCore resources, and the AWS CLI. Turn on outbound identity federation once per account: `aws iam enable-outbound-web-identity-federation` (it gives the account the issuer URL OpenAI trusts).
- **Okta:** an org with Okta for AI Agents, an admin API token, and the two demo people.
- **OpenAI:** an organization where you can add a workload identity provider (issuer = the account's outbound-federation issuer, audience `https://api.openai.com/v1`), one project per team with a service account, and a mapping per team role (see *OpenAI configuration* below).
- **Local:** Python 3.12+ and [uv](https://docs.astral.sh/uv/).

## Deploy, in order (from this folder)

Everything runs in one AWS account through `AWS_PROFILE` / `AWS_REGION`; Okta and OpenAI IDs come from `config.env` (copy `config.env.example`). Set `AWS_ACCOUNT_ID` there and the scripts refuse to run against any other account.

```bash
set -a; source config.env; set +a
python okta_setup.py                    # Okta: wif-engineering / wif-finance groups + people, sign-in server wif-openai-users + claims
python okta_agent_setup.py              # Okta: AI agent + KMS key, wif-gateway server, connection
python gateway/gateway_setup.py up      # team roles, translators, Gateway, inference targets
python gateway/gateway_obo.py up        # Okta-JWT Gateway, Cedar team rules (no interceptor)
python webid_setup.py up                # IAM web identity: Okta claims STS reads, 2 IAM OIDC providers, team-role trust (the mapping)
python gateway/translator_setup.py up   # ONE translator (person's Okta token → AssumeRoleWithWebIdentity → OpenAI token); retargets
python agent_deploy.py up               # AgentCore Identity providers + Strands agent on Runtime
python agent_direct_deploy.py up        # Direct pattern: Strands agent → OpenAI with the SDK's workload_identity, as the person
python observability_setup.py up        # CloudWatch Transaction Search (account) + Gateway logs and traces → GenAI Observability
python bundles_setup.py up              # 3 AgentCore configuration bundles (wif_model_terra / luna / sol), each pins the agents' model
./run.sh                                # console
```

**Testing without a browser:** `DEMO_USER_PASSWORD=… python scripts/okta_chain_test.py <user>` signs a demo user in and runs both delegation steps directly. Then `gateway/gateway_obo.py test` (Gateway allow/deny), `webid_setup.py test ada|grace` (own team's role allowed, other refused, AWS JWT contents, OpenAI exchange), `agent_deploy.py test ada|grace` and `agent_direct_deploy.py test ada|grace`.

## Cleanup

Remove in reverse:

```bash
python bundles_setup.py down
python agent_direct_deploy.py down
python agent_deploy.py down
python gateway/translator_setup.py down
python gateway/gateway_obo.py down
python gateway/gateway_setup.py down
```

These stay until you remove them by hand: the IAM OIDC providers for Okta (IAM console), the agent's KMS key (schedule deletion), the S3 code bucket, CloudWatch Transaction Search (account-wide), outbound identity federation (`aws iam disable-outbound-web-identity-federation`, account-wide: other workloads may use it), the Okta objects (`wif-*` groups, authorization servers, the AI agent and its app) and the OpenAI provider, mappings and service accounts.

## Costs

You pay for what the demo runs: AgentCore Runtime, Gateway and Identity, Lambda, CloudWatch Logs and Transaction Search spans, one KMS key, an S3 bucket, and OpenAI model usage (billed by OpenAI to each team's project). Run the cleanup when you're done.

## Direct pattern (screens 4 and 5)

The same Strands agent idea, but with **no Gateway**, and still **as the person**:
1. The agent hands the caller's Okta access token to STS as a web identity (`AssumeRoleWithWebIdentity`, IAM OIDC provider = Okta's sign-in server). The team role's trust admits it only for that role's team.
2. Strands' `OpenAIModel(client=AsyncOpenAI(workload_identity=…))` gets a token function bound to that session. The OpenAI SDK calls it for an AWS token, exchanges it, caches the short-lived token and refreshes it.
3. One client and one conversation per person, cached per sign-in.

- The agent's role `OpenAIWifDirectAgentRole` has **no** `GetWebIdentityToken` permission of its own.
- **No** Cedar team rule. Evidence of the person: CloudTrail (the Direct screen's Evidence panel).
- **Package note:** `strands-agents[openai]` pins `openai<3`, but `workload_identity` needs `openai>=3.26`. So depend on `strands-agents==1.58.1` and `openai==3.26.0` directly (verified working together).
- Uses the same two team mappings as the Gateway pattern; the earlier `OpenAIWifDirectAgentRole` mapping is no longer needed.

## OpenAI configuration (dashboard)

- **Workload Identity Provider:** issuer = this account's AWS outbound-federation issuer, audience `https://api.openai.com/v1`.
- **Mappings:**
  - `gateway-engineering`: `sub = arn:aws:iam::111122223333:role/OpenAIWifGatewayEngineeringRole` (your account ID) → Engineering service account.
  - `gateway-finance`: the same with `OpenAIWifGatewayFinanceRole` → Finance service account.
  - Both are sub-only, and serve both patterns. Each AWS JWT still names one person: `source_identity` and `principal_tags.user`.
  - The older person-level mappings (`OpenAIWifUserRole` + team) are left in place but unused. Note: the `aws_team` CEL transformation still fails to evaluate (open issue).

## Files

| Path | What |
|---|---|
| `okta_setup.py` | Okta groups and people, the sign-in authorization server and its claims |
| `okta_agent_setup.py` | Okta for AI Agents setup (agent, KMS JWK, servers, connection, policies, team/groups/login claims) |
| `webid_setup.py` | IAM web identity: Okta access-token claims for STS, the IAM OIDC providers, team-role trust (the mapping); `test` |
| `gateway/translator.py` | the one translator (Lambda): person's Okta token → AssumeRoleWithWebIdentity → AWS JWT → OpenAI token |
| `gateway/translator_setup.py` | deploys it, re-points the team targets, retires per-team translators |
| `agent_direct/main.py`, `agent_direct_deploy.py` | the Direct-pattern agent and its deploy/test |
| `observability_setup.py` | Transaction Search + Gateway APPLICATION_LOGS / TRACES delivery; `status` |
| `bundles_setup.py` | the 3 configuration bundles; the console sends the picked one in W3C `baggage`, the agents read `model_id` from it |
| `gateway/gateway_setup.py` | team roles, translators, targets |
| `gateway/gateway_obo.py` | Okta-JWT Gateway, Cedar, header allowlist; `retire-usage` deletes the earlier usage interceptor + table |
| `agent/main.py` | Strands agent with `@requires_access_token` delegation |
| `agent_deploy.py` | AgentCore Identity + Runtime deploy and test |
| `console/server.py`, `console/web/index.html` | the console |
| `scripts/okta_chain_test.py` | browserless test of the Okta delegation steps |

## Security

This is sample code, for non-production usage. You should work with your security and legal teams to meet your organizational security, regulatory and compliance requirements before deployment. The console listens on `127.0.0.1` only. `config.env` holds your Okta admin API token: keep it private (it is git-ignored). No OpenAI API key, Okta client secret or long-lived AWS key is stored anywhere; every token in the chain is short-lived.

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file. Third-party notices are in [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES).
