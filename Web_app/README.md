# Cloud Patrol — Web Application

A Google Cloud security operations assistant secured by Auth0. Built with FastAPI, it lets authenticated users query IAM audit logs, detect public storage buckets, look up service account roles, and revoke IAM bindings — all enforced by fine-grained authorization and step-up authentication.

## Architecture

<img width="1580" height="656" alt="image" src="https://github.com/user-attachments/assets/ceb6bbbe-8433-41e8-84f0-436f1090b311" />


## Auth0 Features Used

| Feature | Purpose |
|---|---|
| **OIDC / OAuth 2.0** | Primary user login |
| **Token Vault (connect-account)** | Link Google account, acquire federated access token |
| **Fine-Grained Authorization (FGA)** | Per-capability permission check before every agent call |
| **CIBA (Backchannel Auth)** | Out-of-band push notification approval for IAM revocations |

## Request Flow

1. User logs in via Auth0 (OIDC)
2. App links Google account → obtains federated Google OAuth token
3. User sends a message in the chat UI
4. `_classify_intent()` uses Gemini 2.0 Flash to classify into one of four intents
5. `_fga_check()` verifies `user:{email}` has `can_access` on `capability:{intent}` in Auth0 FGA
6. **If denied** → returns "This action is not authorized." No agent is called
7. **If remediation** → CIBA push notification sent to user's device; browser polls `/api/ciba-poll` every 5 seconds; orchestrator runs only after approval
8. **All other intents** → orchestrator called immediately with the federated token

## Intents

| Intent | Example phrase | Requires CIBA |
|---|---|---|
| `iam_changes` | "Show IAM changes in the last 24 hours" | No |
| `bucket_audit` | "Are any storage buckets publicly accessible?" | No |
| `sa_lookup` | "What roles does service account X have?" | No |
| `remediation` | "Revoke role Y from service account X" | **Yes** |

## CIBA Flow (Async)

Remediation requests use a two-step async pattern to avoid browser timeouts:

```
1. chat_post  → initiate CIBA → save auth_req_id to session → redirect immediately
               (user sees "I need your approval" message right away)

2. Browser    → polls /api/ciba-poll every 5s
               → on approval: orchestrator runs, agent result appended, page reloads
               → on decline/timeout: error message shown
```

## Key Files

```
Web_app/
├── app.py                  # FastAPI app — all routes, auth, FGA, CIBA, orchestrator call
├── templates/
│   ├── base.html           # Shared HTML base
│   ├── login.html          # Login landing page
│   └── chat.html           # Chat UI with sidebar, markdown rendering, CIBA polling JS
├── static/
│   └── css/style.css
└── requirements.txt
```

## Environment Variables

```env
# Auth0
AUTH0_DOMAIN=
AUTH0_CLIENT_ID=
AUTH0_CLIENT_SECRET=
AUTH0_AUDIENCE=
AUTH0_SECRET=
AUTH0_CONNECTION_NAME=        # e.g. google-oauth2

# App
APP_BASE_URL=http://127.0.0.1:5000
APP_SECRET_KEY=

# Auth0 FGA
FGA_API_HOST=api.us1.fga.dev
FGA_STORE_ID=
FGA_CLIENT_ID=
FGA_CLIENT_SECRET=
FGA_API_TOKEN_ISSUER=auth.fga.us
FGA_API_AUDIENCE=https://api.us1.fga.dev/
FGA_AUTHORIZATION_MODEL_ID=

# Google Cloud / Vertex AI
GOOGLE_CLOUD_PROJECT=
GOOGLE_CLOUD_LOCATION=us-central1
GOOGLE_CLOUD_AGENT_ORCHESTRATOR=   # Reasoning Engine resource name
```

## Running Locally

```bash
cd Web_app
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 5000 --reload
```
## Expected Output
<img width="1066" height="985" alt="image" src="https://github.com/user-attachments/assets/af902431-41b9-4fd0-ae57-c62bb88fe20e" />


