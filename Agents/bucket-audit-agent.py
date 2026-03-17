import os
import vertexai
from vertexai.preview import reasoning_engines
from dotenv import load_dotenv
import logging

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class BucketAuditAgent:
    """Specialist agent that finds publicly accessible Cloud Storage buckets."""

    def set_up(self):
        self._access_token = None
        self._project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")

        def find_public_buckets() -> str:
            """
            List all Cloud Storage buckets in the project and identify any that
            are publicly accessible (grant access to allUsers or
            allAuthenticatedUsers).

            Returns:
                A report of public buckets found, including which roles are
                granted to the public principal on each bucket.
            """
            import requests

            project_id = self._project_id
            token = self._access_token

            if not token:
                return "Error: No access token available. Please re-authenticate."
            if not project_id:
                return "Error: GOOGLE_CLOUD_PROJECT is not set."

            headers = {"Authorization": f"Bearer {token}"}

            # Step 1: list all buckets in the project
            list_url = "https://storage.googleapis.com/storage/v1/b"
            try:
                resp = requests.get(
                    list_url,
                    headers=headers,
                    params={"project": project_id},
                    timeout=30,
                )
                resp.raise_for_status()
                buckets = resp.json().get("items", [])
            except requests.HTTPError as exc:
                return f"Storage API error {exc.response.status_code}: {exc.response.text}"
            except Exception as exc:
                return f"Failed to list buckets: {exc}"

            if not buckets:
                return "No Cloud Storage buckets found in this project."

            # Step 2: check IAM policy on each bucket
            PUBLIC_PRINCIPALS = {"allUsers", "allAuthenticatedUsers"}
            public_buckets = []

            for bucket in buckets:
                bucket_name = bucket["name"]
                iam_url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/iam"
                try:
                    iam_resp = requests.get(iam_url, headers=headers, timeout=30)
                    iam_resp.raise_for_status()
                    bindings = iam_resp.json().get("bindings", [])
                except Exception:
                    continue

                exposed_roles = []
                for binding in bindings:
                    members = set(binding.get("members", []))
                    overlap = members & PUBLIC_PRINCIPALS
                    if overlap:
                        exposed_roles.append(
                            f"{binding['role']} granted to {', '.join(overlap)}"
                        )

                if exposed_roles:
                    public_buckets.append((bucket_name, exposed_roles))

            if not public_buckets:
                return (
                    f"All {len(buckets)} bucket(s) checked — none are publicly accessible. "
                    "No allUsers or allAuthenticatedUsers bindings found."
                )

            lines = [
                f"WARNING: Found {len(public_buckets)} publicly accessible bucket(s) "
                f"out of {len(buckets)} total:\n"
            ]
            for name, roles in public_buckets:
                lines.append(f"• gs://{name}")
                for role in roles:
                    lines.append(f"    - {role}")

            return "\n".join(lines)

        self._agent = reasoning_engines.LangchainAgent(
            model="gemini-2.5-pro",
            tools=[find_public_buckets],
            model_kwargs={"temperature": 0},
            system_instruction=(
                "You are a cloud security auditor specialising in Google Cloud Storage.\n\n"
                "RULES:\n"
                "- You do NOT have access to bucket data yourself.\n"
                "- You MUST call find_public_buckets to answer questions about public buckets.\n"
                "- Reply with ONLY the bucket name and the exact role and principal from the tool result.\n"
                "- Do NOT explain what allUsers or allAuthenticatedUsers means.\n"
                "- Do NOT add recommendations, warnings, or any extra commentary.\n"
                "- If no public buckets are found, say only: 'No public buckets found.'\n"
                "- NEVER fabricate bucket names or IAM policies.\n"
            ),
        )
        self._agent.set_up()

    def query(self, *, input: str, user_id: str = "anonymous", access_token: str = None) -> dict:
        self._access_token = access_token
        self._user_id = user_id
        logger.info("BucketAuditAgent query user_id=%s", user_id)
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

    print("Deploying Bucket Audit Agent...")
    remote_agent = reasoning_engines.ReasoningEngine.create(
        BucketAuditAgent(),
        requirements=requirements,
        display_name="bucket-audit-agent",
    )
    print(f"Deployment complete! Resource name: {remote_agent.resource_name}")


if __name__ == "__main__":
    main()
