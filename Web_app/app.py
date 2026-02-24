import os
import asyncio
import inspect
from functools import wraps
from typing import Any

from dotenv import find_dotenv, load_dotenv
from authlib.integrations.base_client.errors import MismatchingStateError
from authlib.integrations.flask_client import OAuth
from flask import Flask, jsonify, redirect, request, session, url_for
from auth0_api_python import ApiClient, ApiClientOptions

load_dotenv(find_dotenv())

# Initialize OAuth globally
oauth = OAuth()


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"Set {name} before starting the web app.")
    return value


def login_required(func):
    @wraps(func)
    def wrapped(*args: Any, **kwargs: Any):
        if "user" not in session:
            return jsonify({"error": "Unauthorized. Log in first."}), 401
        result = func(*args, **kwargs)
        if inspect.iscoroutine(result):
            return asyncio.run(result)
        return result

    return wrapped


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = _required_env("FLASK_SECRET_KEY")
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = (
        os.environ.get("COOKIE_SECURE", "false").lower() == "true"
    )

    # Store config on the app object so routes can see them
    app.config["AUTH0_DOMAIN"] = _required_env("AUTH0_DOMAIN")
    app.config["AUTH0_CLIENT_ID"] = _required_env("AUTH0_CLIENT_ID")
    app.config["AUTH0_CLIENT_SECRET"] = _required_env("AUTH0_CLIENT_SECRET")
    app.config["AUTH0_AUDIENCE"] = _required_env("AUTH0_AUDIENCE")  
    app.config["CONNECTION_NAME"] = _required_env("CONNECTION_NAME")
    app.config["RETURN_TO_URL"] = os.environ.get(
        "APP_LOGOUT_RETURN_TO", "http://localhost:5000/"
    )
    auth0_audience = (
        os.environ.get("AUTH0_AUDIENCE")
        or f"https://{_required_env('AUTH0_DOMAIN')}/api/v2/"
    )

    # Initialize the AI API Client and attach to app
    app.api_client = ApiClient(
        ApiClientOptions(
            domain=app.config["AUTH0_DOMAIN"],
            client_id=app.config["AUTH0_CLIENT_ID"],
            client_secret=app.config["AUTH0_CLIENT_SECRET"],
            audience=app.config["AUTH0_AUDIENCE"],
        )
    )

    oauth.init_app(app)
    oauth.register(
        "auth0",
        client_id=app.config["AUTH0_CLIENT_ID"],
        client_secret=app.config["AUTH0_CLIENT_SECRET"],
        server_metadata_url=(
            f"https://{app.config['AUTH0_DOMAIN']}/.well-known/openid-configuration"
        ),
        client_kwargs={
            "scope": "openid profile email offline_access invoke:vertex", # Added new scope            # Adding audience here ensures the library handles it during the handshake
            "extra_params": {"audience": app.config["AUTH0_AUDIENCE"]} 
        },
        audience=app.config["AUTH0_AUDIENCE"],
    )

    # --- ROUTES ---

    @app.get("/login")
    def login():
        # Ensure we are explicitly requesting the audience during the redirect
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for("callback", _external=True),
            audience=app.config["AUTH0_AUDIENCE"],
        )

    @app.get("/callback")
    def callback():
        try:
            token = oauth.auth0.authorize_access_token()
            userinfo = token.get("userinfo")
            is_connect_flow = session.pop("is_connect_flow", False)
            access_token = session.get("user", {}).get("access_token") if is_connect_flow else token.get("access_token")
            # CRITICAL: Store the access_token for the chat exchange!
            session["user"] = {
                "sub": userinfo.get("sub"),
                "name": userinfo.get("name"),
                "email": userinfo.get("email"),
                "access_token": access_token,
            }
            return redirect(session.pop("post_auth_redirect", url_for("index")))
        except MismatchingStateError:
            session.clear()
            return jsonify({"error": "State mismatch"}), 400

    @app.get("/connect/google")
    @login_required
    def connect_account():
        connect_url = f"https://{app.config['AUTH0_DOMAIN']}/connect"
        session["is_connect_flow"] = True
        session["post_auth_redirect"] = url_for("chat")
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for("callback", _external=True),
            connection=app.config["CONNECTION_NAME"],
            prompt="consent",
            access_type="offline",
            authorize_url=connect_url,
        )

    @app.route("/chat", methods=["POST", "GET"])
    @login_required
    async def chat():
        print("11111111")
        auth0_token = session["user"].get("access_token")
        print(f"Auth0 token: {auth0_token}")
        try:
            # Call the AI SDK attached to the app
            connection_token_data = await app.api_client.get_access_token_for_connection(
                {
                    "connection": app.config["CONNECTION_NAME"],
                    "access_token": auth0_token,
                }
            )
            print(f"Connection token data: {connection_token_data}")
            if not connection_token_data:
                return jsonify({"error": "No token in Vault. Connect first."}), 404

            external_token = connection_token_data.get("access_token")
            return jsonify({"status": "Success", "preview": external_token[:10]})

        except Exception as e:
            print(f"Error: {e}")
            return jsonify({"error": str(e)}), 500

    @app.get("/")
    def index():
        return jsonify({"authenticated": "user" in session, "user": session.get("user")})

    @app.get("/logout")
    def logout():
        session.clear()
        logout_url = (
            f"https://{app.config['AUTH0_DOMAIN']}/v2/logout"
            f"?client_id={app.config['AUTH0_CLIENT_ID']}&returnTo={app.config['RETURN_TO_URL']}"
        )
        return redirect(logout_url)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)