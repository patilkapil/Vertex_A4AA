import os
import vertexai
from vertexai.preview import reasoning_engines
from dotenv import load_dotenv
import logging

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RemediationAgent:
    """
    Specialist agent that revokes an IAM binding for a service account principal
    on a project. This agent performs a destructive write action and should only
    be invoked after CIBA step-up approval has been confirmed in app.py.
    """

    def set_up(self):
        self._access_token = None
        self._project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")

        def revoke_service_account_binding(
            service_account_email: str,
            role: str,
        ) -> str:
            """
            Revoke a specific IAM role binding from a service account principal
            at the project level.

            This performs a read-modify-write on the project IAM policy:
            1. GET the current policy
            2. Remove the specified member+role binding
            3. SET the modified policy

            Args:
                service_account_email: The service account email to remove, e.g.
                    "my-sa@my-project.iam.gserviceaccount.com"
                role: The IAM role to revoke, e.g. "roles/editor" or
                    "roles/storage.admin"

            Returns:
                A confirmation message if successful, or an error description.
            """
            import requests

            project_id = self._project_id
            token = self._access_token

            if not token:
                return "Error: No access token available. Please re-authenticate."
            if not project_id:
                return "Error: GOOGLE_CLOUD_PROJECT is not set."

            member = f"serviceAccount:{service_account_email}"
            base_url = (
                f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}"
            )
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            # Step 1: get current IAM policy
            try:
                get_resp = requests.post(
                    f"{base_url}:getIamPolicy",
                    headers=headers,
                    json={"options": {"requestedPolicyVersion": 1}},
                    timeout=30,
                )
                get_resp.raise_for_status()
                policy = get_resp.json()
            except requests.HTTPError as exc:
                return (
                    f"Failed to retrieve IAM policy "
                    f"({exc.response.status_code}): {exc.response.text}"
                )
            except Exception as exc:
                return f"Failed to retrieve IAM policy: {exc}"

            # Step 2: find and remove the binding
            bindings = policy.get("bindings", [])
            original_count = sum(len(b.get("members", [])) for b in bindings)
            found = False
            new_bindings = []

            for binding in bindings:
                if binding.get("role") == role:
                    members = [m for m in binding.get("members", []) if m != member]
                    if len(members) < len(binding.get("members", [])):
                        found = True
                    if members:
                        new_bindings.append({**binding, "members": members})
                    # drop the binding entirely if no members remain
                else:
                    new_bindings.append(binding)

            if not found:
                return (
                    f"No binding found for {member} with role {role} "
                    f"on project {project_id}. Nothing to revoke."
                )

            policy["bindings"] = new_bindings

            # Step 3: set the modified policy
            try:
                set_resp = requests.post(
                    f"{base_url}:setIamPolicy",
                    headers=headers,
                    json={"policy": policy},
                    timeout=30,
                )
                set_resp.raise_for_status()
            except requests.HTTPError as exc:
                return (
                    f"Failed to update IAM policy "
                    f"({exc.response.status_code}): {exc.response.text}"
                )
            except Exception as exc:
                return f"Failed to update IAM policy: {exc}"

            return (
                f"Successfully revoked {role} from {member} on project {project_id}. "
                f"The binding has been removed from the project IAM policy."
            )

        def list_service_account_roles(service_account_email: str) -> str:
            """
            List all IAM roles currently assigned to a service account at the
            project level. Use this to find the exact role ID before revoking,
            or when revoke_service_account_binding reports the binding was not found.

            Args:
                service_account_email: The service account email to look up, e.g.
                    "my-sa@my-project.iam.gserviceaccount.com"

            Returns:
                All roles assigned to that service account on the project,
                showing the exact role IDs as stored in the IAM policy.
            """
            import requests

            project_id = self._project_id
            token = self._access_token

            if not token:
                return "Error: No access token available. Please re-authenticate."
            if not project_id:
                return "Error: GOOGLE_CLOUD_PROJECT is not set."

            member = f"serviceAccount:{service_account_email}"
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            try:
                resp = requests.post(
                    f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy",
                    headers=headers,
                    json={"options": {"requestedPolicyVersion": 1}},
                    timeout=30,
                )
                resp.raise_for_status()
                policy = resp.json()
            except requests.HTTPError as exc:
                return f"Failed to retrieve IAM policy ({exc.response.status_code}): {exc.response.text}"
            except Exception as exc:
                return f"Failed to retrieve IAM policy: {exc}"

            matched_roles = [
                binding["role"]
                for binding in policy.get("bindings", [])
                if member in binding.get("members", [])
            ]

            if not matched_roles:
                return (
                    f"No roles found for {member} on project {project_id}. "
                    f"The binding may exist at folder or organization level instead."
                )

            lines = [f"Exact role IDs assigned to {member} on project {project_id}:"]
            for role in matched_roles:
                lines.append(f"  - {role}")
            return "\n".join(lines)

        self._agent = reasoning_engines.LangchainAgent(
            model="gemini-2.5-pro",
            tools=[list_service_account_roles, revoke_service_account_binding],
            model_kwargs={"temperature": 0},
            system_instruction=(
                "You are a security remediation agent for Google Cloud IAM.\n\n"
                "RULES:\n"
                "- This action has already been approved via out-of-band user verification.\n"
                "- If the user does not specify an exact role, call list_service_account_roles FIRST to find the exact role ID.\n"
                "- If revoke_service_account_binding reports the binding was not found, immediately call list_service_account_roles to show what roles actually exist for that service account.\n"
                "- Once the exact role ID is confirmed, call revoke_service_account_binding.\n"
                "- Show the exact role IDs from the tool — never guess or shorten them.\n"
                "- Confirm exactly what was revoked in your response.\n"
                "- NEVER fabricate confirmation of a revocation that did not happen.\n"
            ),
        )
        self._agent.set_up()

    def query(self, *, input: str, user_id: str = "anonymous", access_token: str = None) -> dict:
        self._access_token = access_token
        self._user_id = user_id
        logger.info("RemediationAgent query user_id=%s", user_id)
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

    print("Deploying Remediation Agent...")
    remote_agent = reasoning_engines.ReasoningEngine.create(
        RemediationAgent(),
        requirements=requirements,
        display_name="remediation-agent",
    )
    print(f"Deployment complete! Resource name: {remote_agent.resource_name}")


if __name__ == "__main__":
    main()
