# Cloud Patrol

A Google Cloud security operations assistant that combines **Vertex AI Agent Engine**, **Auth0 for AI Agents** to let authenticated users audit and remediate IAM issues — all running under their own Google identity.

## What It Does

| Capability | Description |
|---|---|
| **IAM Audit** | Query Cloud Audit Logs for IAM policy changes in the last 24 hours |
| **Bucket Exposure** | Detect publicly accessible Cloud Storage buckets |
| **SA Role Lookup** | List exact IAM roles assigned to a service account |
| **IAM Remediation** | Revoke an IAM binding — gated by out-of-band push approval (CIBA) |

## How Auth0 Secures It

| Feature | Role |
|---|---|
| **OIDC / OAuth 2.0** | Primary user login |
| **Token Vault** | Links Google account, acquires federated access token passed to agents |
| **Fine-Grained Authorization (FGA)** | Checks per-capability permissions before every agent call |
| **CIBA (Backchannel Auth)** | Sends push notification to user's device for step-up approval on remediation |

## Architecture

```
User (Browser)
  │
  ▼
Web App (FastAPI)                         ← Web_app/
  ├── Auth0 OIDC Login
  ├── Google Account Linking (Token Vault)
  ├── Gemini 2.0 Flash — Intent Classifier
  ├── Auth0 FGA — Capability Check
  └── Auth0 CIBA — Step-up for Remediation
        │
        ▼
  Vertex AI Agent Engine                  ← Agents/
    Security Orchestrator (gemini-2.5-pro)
      ├── IAM Changes Agent   → Cloud Logging API
      ├── Bucket Audit Agent  → Cloud Storage API
      └── Remediation Agent   → Cloud Resource Manager API
```

## Repository Structure

```
├── Web_app/                        # FastAPI web application
│   ├── app.py                      # All routes, auth, FGA, CIBA, orchestrator calls
│   ├── templates/
│   │   ├── login.html              # Login landing page
│   │   └── chat.html               # Chat UI with CIBA polling
│   ├── static/
│   ├── requirements.txt
│   ├── sample.env                  # Environment variable template
│   └── README.md
│
└── Agents/                         # Vertex AI Reasoning Engine agents
    ├── security-orchestrator-agent.py   # Routes queries to specialists
    ├── iam-changes-agent.py             # Cloud Logging audit queries
    ├── bucket-audit-agent.py            # GCS public bucket detection
    ├── remediation-agent.py             # IAM role lookup and revocation
    ├── requirements.txt
    ├── sample.env                       # Environment variable template
    └── README.md
```

## Quick Start

### 1. Deploy Agents
```bash
cd Agents
pip install -r requirements.txt
# Deploy specialists first, then orchestrator — see Agents/README.md
```

### 2. Run Web App
```bash
cd Web_app
pip install -r requirements.txt
cp sample.env .env        # fill in your values
uvicorn app:app --host 0.0.0.0 --port 5000 --reload
```

### 3. Configure Auth0
- Create an application with OIDC and CIBA enabled
- Set up a Google social connection for Token Vault
- Configure FGA store with `capability` type and `can_access` relation

## Prerequisites

- Google Cloud project with Cloud Logging, Cloud Storage, and Cloud Resource Manager APIs enabled
- Auth0 tenant with FGA and CIBA configured
- Vertex AI Agent Engine enabled in your GCP project
