# Cloud Patrol — Vertex AI Agent Engine

Multi-agent security operations system built on **Vertex AI Agent Engine** (Reasoning Engines). Uses a **LangChain orchestrator → specialist** pattern with **Gemini 2.5 Pro**, where each agent is deployed as a managed Reasoning Engine resource on Google Cloud.

## Architecture

```
Security Orchestrator Agent
  │
  ├── Intent: iam_changes   → IAM Changes Agent   → Cloud Logging API
  ├── Intent: bucket_audit  → Bucket Audit Agent  → Cloud Storage API
  ├── Intent: sa_lookup     → Remediation Agent   → Cloud Resource Manager API
  └── Intent: remediation   → Remediation Agent   → Cloud Resource Manager API
```

All agents receive the user's **federated Google OAuth token** passed through from the web app, so every Google API call runs under the authenticated user's identity — not a service account.

## Agents

### Security Orchestrator (`security-orchestrator-agent.py`)
- Model: `gemini-2.5-pro`
- Receives the user query and routes to the correct specialist via `call_specialist_agent(agent_type, user_query)`
- Passes `access_token` through to each specialist at query time
- Does **not** call any Google Cloud APIs directly

### IAM Changes Agent (`iam-changes-agent.py`)
- Model: `gemini-2.5-pro`
- **Tool**: `get_iam_changes(hours_back=24)`
- Calls **Cloud Logging API** (`entries:list`) filtering for `SetIamPolicy` audit events
- Extracts `bindingDeltas` (ADD/REMOVE) from log entries

### Bucket Audit Agent (`bucket-audit-agent.py`)
- Model: `gemini-2.5-pro`
- **Tool**: `find_public_buckets()`
- Lists all GCS buckets via **Cloud Storage API**
- Checks each bucket's IAM policy for `allUsers` or `allAuthenticatedUsers` members

### Remediation Agent (`remediation-agent.py`)
- Model: `gemini-2.5-pro`
- **Tool 1**: `list_service_account_roles(service_account_email)` — reads project IAM and returns exact role IDs for a service account
- **Tool 2**: `revoke_service_account_binding(service_account_email, role)` — read-modify-write on project IAM policy to remove a binding
- Calls **Cloud Resource Manager API** (`projects.getIamPolicy` / `projects.setIamPolicy`)
- Handles both `sa_lookup` (read) and `remediation` (write) intents

## Token Flow

```
Web App (app.py)
  └── Orchestrator.query(access_token=federated_google_token)
        └── self._access_token = token
              └── call_specialist_agent() → ReasoningEngine.query(access_token=self._access_token)
                    └── SpecialistAgent.query(access_token=token)
                          └── self._access_token → Google API call (Bearer token)
```

The token is never persisted in the container — it flows at runtime through each `.query()` call via the closure pattern inside `set_up()`.

## Deployment Order

Deploy in this order — each step requires the resource name from the previous:

```bash
# 1. Deploy specialist agents
python iam-changes-agent.py
python bucket-audit-agent.py
python remediation-agent.py

# 2. Add resource names to .env
GOOGLE_CLOUD_AGENT_ENGINE_ID_IAM_CHANGES=projects/.../reasoningEngines/...
GOOGLE_CLOUD_AGENT_ENGINE_ID_BUCKET_AUDIT=projects/.../reasoningEngines/...
GOOGLE_CLOUD_AGENT_ENGINE_ID_REMEDIATION=projects/.../reasoningEngines/...

# 3. Deploy orchestrator
python security-orchestrator-agent.py

# 4. Add orchestrator resource name to Web_app/.env
GOOGLE_CLOUD_AGENT_ORCHESTRATOR=projects/.../reasoningEngines/...
```

## Environment Variables

```env
GOOGLE_CLOUD_PROJECT=
GOOGLE_CLOUD_LOCATION=us-central1
GOOGLE_CLOUD_STAGING_BUCKET=gs://your-bucket

# Set after deploying each specialist
GOOGLE_CLOUD_AGENT_ENGINE_ID_IAM_CHANGES=
GOOGLE_CLOUD_AGENT_ENGINE_ID_BUCKET_AUDIT=
GOOGLE_CLOUD_AGENT_ENGINE_ID_REMEDIATION=

# Set after deploying orchestrator
GOOGLE_CLOUD_AGENT_SECURITY_ORCHESTRATOR=
```

## Files

```
Ageent_POCs/
├── security-orchestrator-agent.py  # Orchestrator — routes to specialists
├── iam-changes-agent.py            # Specialist — Cloud Logging audit queries
├── bucket-audit-agent.py           # Specialist — GCS public bucket detection
└── remediation-agent.py            # Specialist — IAM role lookup and revocation
```
