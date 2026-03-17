import os
import time
import uuid
import logging
from functools import wraps
from typing import Any, Dict, Optional, Tuple, Union

import vertexai
from vertexai.preview import reasoning_engines
from vertexai.generative_models import GenerativeModel
from google.oauth2.credentials import Credentials
from openfga_sdk.client import OpenFgaClient, ClientConfiguration
from openfga_sdk.client.models import ClientCheckRequest
from openfga_sdk.credentials import Credentials as FgaCredentials, CredentialConfiguration
from dotenv import load_dotenv
from auth0_fastapi.stores.cookie_transaction_store import CookieTransactionStore
from auth0_fastapi.stores.stateless_state_store import StatelessStateStore
from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import (
    ConnectAccountOptions,
    LogoutOptions,
    StartInteractiveLoginOptions,
    StateData,
    TransactionData,
)
from auth0_server_python.error import ApiError, PollingApiError
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware


load_dotenv()

APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "your-secret-key-here")

AUTH0_CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
AUTH0_CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
AUTH0_BASE_URL = f"https://{AUTH0_DOMAIN}"
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE")
AUTH0_SECRET = os.getenv("AUTH0_SECRET", "")
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://127.0.0.1:5000").rstrip("/")

# Only standard OIDC scopes for the primary login — provider-specific scopes
# (okta.users.read, read:me:connected_accounts) must NOT be sent here because
# Google rejects them with error 400: invalid_scope.
AUTH0_SCOPE = "openid profile email offline_access"


# Scopes forwarded to the downstream provider (e.g. Google) during the
# connect-account flow.  Must only contain scopes the provider accepts.
# Override via CONNECTED_ACCOUNT_SCOPE env var for non-Google connections
# (e.g. "openid profile email okta.users.read" for Okta).
CONNECTED_ACCOUNT_SCOPE = os.getenv(
    "CONNECTED_ACCOUNT_SCOPE",
    "openid profile email https://www.googleapis.com/auth/cloud-platform",
)

AUTH0_AUTH_PARAMS = {
    "scope": AUTH0_SCOPE,
    "audience": AUTH0_AUDIENCE,
    "prompt": "consent",
    "access_type": "offline",
}
AUTH0_CONNECTION_NAME = os.getenv("AUTH0_CONNECTION_NAME")


# Use Secure cookies only when the app is served over HTTPS.
# Both CookieTransactionStore and StatelessStateStore default to secure=True,
# which causes browsers to silently drop the cookies over plain HTTP, leading
# to MissingTransactionError on the callback.
_USE_SECURE_COOKIES = (APP_BASE_URL or "").startswith("https://")


class _AppCookieTransactionStore(CookieTransactionStore):
    """Overrides secure flag so HTTP (local dev) flows work correctly."""

    async def set(
        self,
        identifier: str,
        value: TransactionData,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options.")
        response: Response = options["response"]
        encrypted_value = self.encrypt(identifier, value.model_dump())
        response.set_cookie(
            key=self.cookie_name,
            value=encrypted_value,
            path="/",
            samesite="Lax",
            secure=_USE_SECURE_COOKIES,
            httponly=True,
            max_age=300,  # 5 minutes — enough for any normal login flow
        )


class _AppStatelessStateStore(StatelessStateStore):
    """Overrides secure flag so HTTP (local dev) flows work correctly."""

    async def set(
        self,
        identifier: str,
        state: Union[StateData, Dict[str, Any]],
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        if options is None or "response" not in options:
            raise ValueError("Response object is required in store options.")
        response: Response = options["response"]
        state_dict = state.dict() if hasattr(state, "dict") and callable(state.dict) else state
        encrypted_data = self.encrypt(identifier, state_dict)
        chunk_size = self.max_cookie_size - len(self.cookie_name) - 10
        for i in range(0, len(encrypted_data), chunk_size):
            chunk_name = f"{self.cookie_name}_{i // chunk_size}"
            response.set_cookie(
                key=chunk_name,
                value=encrypted_data[i : i + chunk_size],
                path="/",
                httponly=True,
                secure=_USE_SECURE_COOKIES,
                samesite="Lax",
                max_age=self.expiration,
            )


_store_secret = AUTH0_SECRET or APP_SECRET_KEY
auth_client = ServerClient(
    domain=AUTH0_DOMAIN,
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    secret=_store_secret,
    redirect_uri=f"{APP_BASE_URL}/auth/callback",
    authorization_params=AUTH0_AUTH_PARAMS,
    transaction_store=_AppCookieTransactionStore(_store_secret, cookie_name="_a0_tx"),
    state_store=_AppStatelessStateStore(_store_secret, cookie_name="_a0_session"),
)

app = FastAPI(title="Vertex Reasoning Engine Powered by Auth0")
app.add_middleware(SessionMiddleware, secret_key=APP_SECRET_KEY, same_site="lax")
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

def _store_options(request: Request, response: Response) -> Dict[str, Any]:
    """Translate FastAPI request/response into the structure expected by auth0_server_python."""
    return {"request": request, "response": response}


def _merge_set_cookie(source: Response, target: Response) -> None:
    """Copy Set-Cookie headers from the Auth0 helper onto the outgoing response."""
    if not source or not target:
        return
    for cookie in source.headers.getlist("set-cookie"):
        target.headers.append("set-cookie", cookie)


async def fetch_federated_tokens(request: Request, access_token: Optional[str] = None) -> Tuple[Dict[str, Any], Response]:
    """List connected accounts via the SDK, then exchange for per-connection tokens.

    The SDK's list_connected_accounts() internally fetches a token scoped to the
    MyAccount API audience with read:me:connected_accounts — the primary session
    token stored in request.session is NOT the right token for that API and must
    not be used directly (causes 401).
    """
    state_response = Response()

    # 1. List connected accounts — SDK handles getting the correctly scoped token
    try:
        list_resp = await auth_client.list_connected_accounts(
            store_options=_store_options(request, state_response)
        )
        connected_accounts = [acct.model_dump() for acct in list_resp.accounts]
        logging.info("Found %d connected account(s).", len(connected_accounts))
    except Exception as exc:
        logging.error("Failed to list connected accounts: %s", exc)
        return {"error": "list_connected_accounts_failed", "details": str(exc)}, state_response

    # 2. Exchange primary session (via refresh token) for each connection's token
    federated_tokens = []
    for acct in list_resp.accounts:
        conn_name = acct.connection
        try:
            token = await auth_client.get_access_token_for_connection(
                {"connection": conn_name, "scope": CONNECTED_ACCOUNT_SCOPE},
                store_options=_store_options(request, state_response),
            )
            federated_tokens.append({"connection": conn_name, "token": token})
        except Exception as exc:
            logging.error("Token exchange failed for connection '%s': %s", conn_name, exc)

    return {
        "connected_accounts": connected_accounts,
        "federated_tokens": federated_tokens,
    }, state_response

def requires_auth(handler):
    """Guard routes that require an authenticated profile in the session."""
    @wraps(handler)
    async def wrapped(request: Request, *args, **kwargs):
        if not request.session.get("profile"):
            return RedirectResponse(url="/login", status_code=302)
        return await handler(request, *args, **kwargs)

    return wrapped


async def get_tokenset(request: Request) -> Tuple[Dict[str, Any], Response]:
    """Convenience wrapper used by the token vault API."""
    return await fetch_federated_tokens(request)


@app.get("/")
async def index(request: Request):
    """Render login screen or redirect to chat when already authenticated."""
    if request.session.get("profile"):
        return RedirectResponse(url="/chat", status_code=302)
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "session": request.session,
        },
    )


@app.get("/login")
async def login(request: Request):
    """Start interactive Auth0 login and reset any stale session state."""
    request.session.clear()
    temp_response = Response()
    try:
        auth_url = await auth_client.start_interactive_login(
            options=StartInteractiveLoginOptions(
                app_state={"returnTo": f"{APP_BASE_URL}/chat"},
                authorization_params=AUTH0_AUTH_PARAMS,
            ),
            store_options=_store_options(request, temp_response),
        )
    except Exception as exc:  # noqa: BLE001
        logging.exception("Failed to start Auth0 login: %s", exc)
        return RedirectResponse(url="/", status_code=302)

    outgoing = RedirectResponse(url=auth_url, status_code=302)
    _merge_set_cookie(temp_response, outgoing)
    return outgoing


@app.get("/auth/callback")
async def callback(request: Request):
    """Handle Auth0 login callback and kick off connect-account flow when needed."""
    response = Response()
    # Check if this is a secondary redirect from the Connect Account flow
    if "connect_code" in request.query_params:
        target = f"{APP_BASE_URL}/connect-account/callback?{request.url.query}"
        outgoing = RedirectResponse(url=target, status_code=302)
        _merge_set_cookie(response, outgoing)
        return outgoing
    try:
        result = await auth_client.complete_interactive_login(
            str(request.url),
            store_options=_store_options(request, response),
        )
    except Exception as exc:
        logging.exception("Error completing Auth0 login: %s", exc)
        return RedirectResponse(url="/login", status_code=302)

    state_data = result.get("state_data") or {}
    token_sets = state_data.get("token_sets") or []
    primary_token = token_sets[0].get("access_token") if token_sets else None
    # Store essential data in session immediately
    userinfo = state_data.get("user") or {}
    request.session["profile"] = {
        "user_id": userinfo.get("sub"),
        "name": userinfo.get("name"),
        "email": userinfo.get("email"),
    }
    request.session["access_token"] = primary_token
    request.session["session_id"] = str(uuid.uuid4())

    # PREPARE REDIRECT: Go to Connect Flow instead of Chat
    outgoing = RedirectResponse(url="/connect-account/start", status_code=302)
    _merge_set_cookie(response, outgoing)
    return outgoing




@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    temp_response = Response()
    try:
        logout_url = await auth_client.logout(
            options=LogoutOptions(return_to=f"{APP_BASE_URL}/"),
            store_options=_store_options(request, temp_response),
        )
    except Exception as exc:  # noqa: BLE001
        logging.exception("Auth0 logout failed: %s", exc)
        return RedirectResponse(url="/", status_code=302)

    outgoing = RedirectResponse(url=logout_url, status_code=302)
    _merge_set_cookie(temp_response, outgoing)
    return outgoing


@app.get("/connect-account/start")
@requires_auth
async def connect_account_start(request: Request):
    """Begin the Auth0 connect-account flow using the primary session profile."""
    if not AUTH0_CONNECTION_NAME:
        logging.warning("AUTH0_CONNECTION_NAME is not set; skipping connect-account flow.")
        return RedirectResponse(url="/chat", status_code=302)

    temp_response = Response()

    # Get profile from session (populated in /auth/callback)
    profile = request.session.get("profile", {})
    login_hint = profile.get("email")

    scopes = CONNECTED_ACCOUNT_SCOPE.split()

    try:
        # This triggers the Auth0 Account Linking flow
        connect_url = await auth_client.start_connect_account(
            options=ConnectAccountOptions(
                connection=AUTH0_CONNECTION_NAME,
                scopes=scopes,
                app_state={"returnTo": f"{APP_BASE_URL}/chat"},
                authorization_params={"login_hint": login_hint} if login_hint else None,
            ),
            store_options=_store_options(request, temp_response),
        )
    except Exception as exc:
        logging.exception("Automatic connect start failed: %s", exc)
        return RedirectResponse(url="/chat", status_code=302)

    outgoing = RedirectResponse(url=connect_url, status_code=302)
    _merge_set_cookie(temp_response, outgoing)
    return outgoing


@app.get("/connect-account/callback")
@requires_auth
async def connect_account_callback(request: Request):
    """Complete the connect-account flow and persist newly acquired tokens."""
    temp_response = Response()
    try:
        await auth_client.complete_connect_account(
            str(request.url),
            store_options=_store_options(request, temp_response),
        )
        request.session["connected_account_status"] = True
        
        primary_token = request.session.get("access_token")
        tokens_payload, _ = await fetch_federated_tokens(request, access_token=primary_token)
        federated_entries = tokens_payload.get("federated_tokens") or []
        federated_token_value = None
        if isinstance(federated_entries, list) and federated_entries:
            first_entry = federated_entries[0]
            if isinstance(first_entry, dict):
                federated_token_value = first_entry.get("token")
        logging.info("Federated token acquired for connection callback")
    except Exception as exc:
        logging.exception("Connect callback failed: %s", exc)
        request.session["connected_account_status"] = False
  
    outgoing = RedirectResponse(url="/chat", status_code=302)
    _merge_set_cookie(temp_response, outgoing)
    return outgoing
 

@app.get("/chat")
@requires_auth
async def chat(request: Request):
    profile = request.session.get("profile", {})
    messages = request.session.get("chat_messages", [])
    ciba_pending = request.session.get("ciba_pending", False)
    ciba_poll_interval = request.session.get("ciba_poll_interval", 5)
    return templates.TemplateResponse(
        "chat.html",
        {
            "request": request,
            "user": profile,
            "messages": messages,
            "ciba_pending": ciba_pending,
            "ciba_poll_interval": ciba_poll_interval,
        },
    )


@app.post("/chat")
@requires_auth
async def chat_post(request: Request):
    form = await request.form()
    user_message = (form.get("message") or "").strip()
    messages = request.session.get("chat_messages", [])

    if not user_message:
        return RedirectResponse(url="/chat", status_code=302)

    messages.append({"sender": "user", "message": user_message})

    try:
        tokens_payload, _ = await fetch_federated_tokens(request)
        federated_entries = tokens_payload.get("federated_tokens") or []
        federated_token = federated_entries[0].get("token") if federated_entries else None

        if not federated_token:
            raise ValueError("No federated Google token found. Please reconnect your Google account.")

        credentials = Credentials(token=federated_token)
        vertexai.init(
            project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
            location=os.environ.get("GOOGLE_CLOUD_LOCATION"),
            credentials=credentials,
        )
        user_email = request.session.get("profile", {}).get("email")

        # 1. Classify intent — app.py has internet, Vertex AI container does not
        intent = _classify_intent(user_message)
        logging.info("Classified intent=%s user=%s", intent, user_email)

        # 2. FGA check — if denied, stop immediately regardless of intent
        if not await _fga_check(user_email, intent):
            logging.warning("FGA DENY user=%s intent=%s", user_email, intent)
            messages.append({"sender": "system", "message": "This action is not authorized."})
            request.session["chat_messages"] = messages
            return RedirectResponse(url="/chat", status_code=302)
        logging.info("FGA ALLOW user=%s intent=%s", user_email, intent)

        # 3. Remediation requires CIBA step-up: initiate and redirect immediately.
        #    The browser will poll /api/ciba-poll; the orchestrator runs there on approval.
        if intent == "remediation":
            user_sub = request.session.get("profile", {}).get("user_id")
            try:
                bc_data = await auth_client.initiate_backchannel_authentication({
                    "login_hint": {"sub": user_sub},
                    "binding_message": "Approve access to the remediation capability",
                })
            except ApiError as exc:
                logging.error("CIBA initiate failed: %s", exc)
                messages.append({"sender": "system", "message": "Failed to send approval request. Please try again."})
                request.session["chat_messages"] = messages
                return RedirectResponse(url="/chat", status_code=302)

            request.session["ciba_pending"] = True
            request.session["ciba_auth_req_id"] = bc_data["auth_req_id"]
            request.session["ciba_deadline"] = time.time() + bc_data.get("expires_in", 300)
            request.session["ciba_poll_interval"] = bc_data.get("interval", 5)
            request.session["ciba_user_message"] = user_message
            request.session["ciba_federated_token"] = federated_token
            request.session["ciba_user_email"] = user_email
            messages.append({
                "sender": "system",
                "message": "I need your approval before I can execute this remediation. I've sent a request to your registered device — please approve it to continue.",
            })
            request.session["chat_messages"] = messages
            return RedirectResponse(url="/chat", status_code=302)

        # 4. Call security orchestrator — passes federated token so specialists
        #    can call Google APIs on behalf of the authenticated user
        _orchestrator_id = os.environ.get("GOOGLE_CLOUD_AGENT_ORCHESTRATOR")
        if not _orchestrator_id:
            raise ValueError("GOOGLE_CLOUD_AGENT_ORCHESTRATOR is not set in .env")
        remote_agent = reasoning_engines.ReasoningEngine(_orchestrator_id)
        response = remote_agent.query(
            input=user_message,
            user_id=user_email,
            access_token=federated_token,
        )
        messages.append({"sender": "agent", "message": extract_response_text(response)})
    except Exception as exc:
        logging.exception("Agent query failed: %s", exc)
        messages.append({"sender": "system", "message": str(exc)})

    request.session["chat_messages"] = messages
    return RedirectResponse(url="/chat", status_code=302)


@app.get("/api/ciba-poll")
@requires_auth
async def ciba_poll(request: Request):
    """Single-attempt CIBA grant check. Called by the browser every N seconds."""
    if not request.session.get("ciba_pending"):
        return JSONResponse({"status": "not_pending"})

    auth_req_id = request.session.get("ciba_auth_req_id")
    deadline = request.session.get("ciba_deadline", 0)
    user_message = request.session.get("ciba_user_message", "")
    federated_token = request.session.get("ciba_federated_token")
    user_email = request.session.get("ciba_user_email", "")
    messages = request.session.get("chat_messages", [])

    if time.time() > deadline:
        _clear_ciba_session(request)
        messages.append({"sender": "system", "message": "The remediation request was not confirmed in time. Please try again."})
        request.session["chat_messages"] = messages
        return JSONResponse({"status": "declined"})

    try:
        await auth_client.backchannel_authentication_grant(auth_req_id)
    except PollingApiError as exc:
        if exc.code == "authorization_pending":
            return JSONResponse({"status": "pending"})
        elif exc.code == "slow_down":
            new_interval = request.session.get("ciba_poll_interval", 5) + (exc.interval or 5)
            request.session["ciba_poll_interval"] = new_interval
            return JSONResponse({"status": "pending", "interval": new_interval * 1000})
        else:
            _clear_ciba_session(request)
            messages.append({"sender": "system", "message": "The remediation request was declined. Please try again or contact your administrator."})
            request.session["chat_messages"] = messages
            return JSONResponse({"status": "declined"})
    except Exception as exc:
        logging.exception("CIBA poll error: %s", exc)
        _clear_ciba_session(request)
        messages.append({"sender": "system", "message": f"An error occurred during approval: {exc}"})
        request.session["chat_messages"] = messages
        return JSONResponse({"status": "error"})

    # CIBA approved — call the orchestrator now
    logging.info("CIBA approved for remediation user=%s", user_email)
    _clear_ciba_session(request)
    try:
        credentials = Credentials(token=federated_token)
        vertexai.init(
            project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
            location=os.environ.get("GOOGLE_CLOUD_LOCATION"),
            credentials=credentials,
        )
        _orchestrator_id = os.environ.get("GOOGLE_CLOUD_AGENT_ORCHESTRATOR")
        remote_agent = reasoning_engines.ReasoningEngine(_orchestrator_id)
        response = remote_agent.query(
            input=user_message,
            user_id=user_email,
            access_token=federated_token,
        )
        messages.append({"sender": "agent", "message": extract_response_text(response)})
    except Exception as exc:
        logging.exception("Orchestrator call failed after CIBA approval: %s", exc)
        messages.append({"sender": "system", "message": f"Approval received but agent call failed: {exc}"})

    request.session["chat_messages"] = messages
    return JSONResponse({"status": "approved"})


def _clear_ciba_session(request: Request) -> None:
    for key in ("ciba_pending", "ciba_auth_req_id", "ciba_deadline",
                "ciba_poll_interval", "ciba_user_message",
                "ciba_federated_token", "ciba_user_email"):
        request.session.pop(key, None)


@app.post("/clear-chat")
@requires_auth
async def clear_chat(request: Request):
    request.session["chat_messages"] = []
    return RedirectResponse(url="/chat", status_code=302)


@app.get("/api/token-vault")
@requires_auth
async def get_token_vault_data(request: Request):
    try:
        tokenset, store_response = await get_tokenset(request)

        if not tokenset:
            response = JSONResponse(
                {
                    "error": "token_fetch_failed",
                    "message": "Token vault is empty. Connect an account to retrieve federated tokens.",
                },
                status_code=400,
            )
            _merge_set_cookie(store_response, response)
            return response

        if tokenset.get("error"):
            status = tokenset.get("status", 400)
            response = JSONResponse(tokenset, status_code=status)
            _merge_set_cookie(store_response, response)
            return response

        vault_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "user": request.session.get("profile", {}).get("email", "Unknown"),
            "connected_accounts": tokenset.get("connected_accounts", []),
            "federated_tokens": tokenset.get("federated_tokens", []),
            "connection": AUTH0_CONNECTION_NAME or "Not configured",
            "audience": f"https://{AUTH0_DOMAIN}/api/v2/",
            "connected_account_status": request.session.get("connected_account_status", False),
        }

        response = JSONResponse(vault_data)
        _merge_set_cookie(store_response, response)
        return response

    except Exception as exc:  # noqa: BLE001
        logging.exception("Error fetching token vault data: %s", exc)
        return JSONResponse(
            {
                "error": str(exc),
                "message": "Failed to fetch token vault data",
            },
            status_code=500,
        )
 
def _classify_intent(user_message: str) -> str:
    """Use Gemini to classify the user's intent into one of four categories."""
    model = GenerativeModel("gemini-2.0-flash")
    result = model.generate_content(
        "Reply with ONLY one word from this list based on the query below:\n"
        "  'iam_changes'  — asking about recent IAM policy changes or audit log events\n"
        "  'bucket_audit' — asking about public or exposed Cloud Storage buckets\n"
        "  'sa_lookup'    — asking what roles or permissions a service account currently has\n"
        "  'remediation'  — asking to revoke, remove, or change an IAM binding\n\n"
        f"Query: {user_message}"
    ).text.strip().lower()
    return result if result in ("iam_changes", "bucket_audit", "sa_lookup", "remediation") else "unknown"


async def _fga_check(user_email: str, intent: str) -> bool:
    """Check Auth0 FGA: can user:{user_email} access agent:{intent}."""
    _raw_issuer = os.getenv("FGA_API_ISSUER") or f"https://{os.getenv('FGA_API_TOKEN_ISSUER', 'auth.fga.us')}"
    _issuer = _raw_issuer.rstrip("/")
    _raw_audience = os.getenv("FGA_API_AUDIENCE", "api.us1.fga.dev")
    _audience = _raw_audience if _raw_audience.startswith("https://") else f"https://{_raw_audience}"
    credentials = FgaCredentials(
        method="client_credentials",
        configuration=CredentialConfiguration(
            api_issuer=_issuer,
            api_audience=_audience,
            client_id=os.getenv("FGA_CLIENT_ID"),
            client_secret=os.getenv("FGA_CLIENT_SECRET"),
        ),
    )
    configuration = ClientConfiguration(
        api_scheme="https",
        api_host=os.getenv('FGA_API_HOST', 'api.us1.fga.dev'),
        store_id=os.getenv("FGA_STORE_ID"),
        authorization_model_id=os.getenv("FGA_AUTHORIZATION_MODEL_ID"),
        credentials=credentials,
    )
    async with OpenFgaClient(configuration) as fga_client:
        body = ClientCheckRequest(
            user=f"user:{user_email}",
            relation="can_access",
            object=f"capability:{intent}",
        )
        response = await fga_client.check(body, options={})
        return bool(response.allowed)


def extract_response_text(response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        return (
            response.get("output")
            or response.get("text")
            or response.get("message")
            or response.get("content")
            or str(response)
        )
    return "Received response from agent."


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)