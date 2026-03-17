import os
import json
import datetime
import vertexai
from vertexai.preview import reasoning_engines
from dotenv import load_dotenv
import logging

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IamChangesAgent:
    """Specialist agent that queries Cloud Audit Logs for IAM policy changes."""

    def set_up(self):
        self._access_token = None
        self._project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")

        def get_iam_changes(hours_back: int = 24) -> str:
            """
            Query Cloud Audit Logs for IAM policy changes (SetIamPolicy calls)
            in the last N hours.

            Args:
                hours_back: How many hours back to search. Defaults to 24.

            Returns:
                A formatted summary of IAM changes found, including who made
                the change, which resource was affected, and when.
            """
            import requests

            project_id = self._project_id
            token = self._access_token

            if not token:
                return "Error: No access token available. Please re-authenticate."
            if not project_id:
                return "Error: GOOGLE_CLOUD_PROJECT is not set."

            since = (
                datetime.datetime.utcnow() - datetime.timedelta(hours=hours_back)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")

            url = "https://logging.googleapis.com/v2/entries:list"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }
            body = {
                "resourceNames": [f"projects/{project_id}"],
                "filter": (
                    f'protoPayload.methodName="SetIamPolicy" '
                    f'AND timestamp>="{since}"'
                ),
                "orderBy": "timestamp desc",
                "pageSize": 50,
            }

            try:
                resp = requests.post(url, headers=headers, json=body, timeout=30)
                resp.raise_for_status()
                data = resp.json()
            except requests.HTTPError as exc:
                return f"Cloud Logging API error {exc.response.status_code}: {exc.response.text}"
            except Exception as exc:
                return f"Request failed: {exc}"

            entries = data.get("entries", [])
            if not entries:
                return (
                    f"[LIVE API RESULT] Cloud Audit Logs queried from {since} to now. "
                    f"No SetIamPolicy events found in the last {hours_back} hours. "
                    f"Do NOT supplement this with any other data."
                )

            lines = [
                f"[LIVE API RESULT] Cloud Audit Logs queried from {since} to now. "
                f"Found {len(entries)} IAM change(s) in the last {hours_back} hours:\n"
            ]
            for entry in entries:
                proto = entry.get("protoPayload", {})
                timestamp = entry.get("timestamp", "unknown time")
                caller = proto.get("authenticationInfo", {}).get("principalEmail", "unknown")
                resource = proto.get("resourceName", "unknown resource")

                # Prefer policyDelta (shows only what changed) over full policy dump
                service_data = proto.get("serviceData") or proto.get("metadata") or {}
                policy_delta = service_data.get("policyDelta", {})
                binding_deltas = policy_delta.get("bindingDeltas", [])

                lines.append(f"• [{timestamp}] {caller} modified {resource}")

                if binding_deltas:
                    for delta in binding_deltas:
                        action = delta.get("action", "UNKNOWN")   # ADD or REMOVE
                        role = delta.get("role", "unknown role")
                        member = delta.get("member", "unknown member")
                        symbol = "+" if action == "ADD" else "-"
                        lines.append(f"    {symbol} [{action}] {role} → {member}")
                else:
                    # Fallback: show full bindings from the request payload
                    bindings = (
                        proto.get("request", {}).get("policy", {}).get("bindings", [])
                    )
                    if bindings:
                        lines.append("    Full policy bindings set (delta unavailable):")
                        for b in bindings:
                            role = b.get("role", "")
                            for member in b.get("members", []):
                                lines.append(f"      {role} → {member}")
                    else:
                        lines.append("    (binding details not available in log entry)")

            return "\n".join(lines)

        self._agent = reasoning_engines.LangchainAgent(
            model="gemini-2.5-pro",
            tools=[get_iam_changes],
            model_kwargs={"temperature": 0},
            system_instruction=(
                "You are a security analyst assistant specialising in Google Cloud IAM.\n\n"
                "RULES:\n"
                "- You do NOT have access to audit log data yourself.\n"
                "- You MUST call get_iam_changes to answer any question about IAM changes.\n"
                "- ONLY report entries returned by the tool marked [LIVE API RESULT].\n"
                "- If the tool says no changes were found, report exactly that — do NOT add examples, guesses, or historical data.\n"
                "- NEVER use your training knowledge to supplement or replace tool results.\n"
                "- ALWAYS show the FULL binding details from the tool result — every role and every member. Never truncate or ask the user if they want to see more.\n"
                "- For each change, show: timestamp, who made the change, which resource, and every binding that was added (+) or removed (-).\n"
                "- Flag any changes made by external or unexpected identities.\n"
            ),
        )
        self._agent.set_up()

    def query(self, *, input: str, user_id: str = "anonymous", access_token: str = None) -> dict:
        self._access_token = access_token
        self._user_id = user_id
        logger.info("IamChangesAgent query user_id=%s", user_id)
        return self._agent.query(input=input)


def main() -> None:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    location = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
    staging_bucket = os.environ.get("GOOGLE_CLOUD_STAGING_BUCKET")

    if not all([project_id, staging_bucket]):
        raise ValueError("GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_STAGING_BUCKET must be set.")

    vertexai.init(project=project_id, location=location, staging_bucket=staging_bucket)

    requirements = [
        "google-cloud-aiplatform[reasoningengine,langchain]",
        "langchain-google-vertexai",
        "cloudpickle==3.0.0",
        "requests",
    ]

    print("Deploying IAM Changes Agent...")
    remote_agent = reasoning_engines.ReasoningEngine.create(
        IamChangesAgent(),
        requirements=requirements,
        display_name="iam-changes-agent",
    )
    print(f"Deployment complete! Resource name: {remote_agent.resource_name}")


if __name__ == "__main__":
    main()
