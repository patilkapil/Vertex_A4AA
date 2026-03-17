import os
import vertexai
from vertexai.preview import reasoning_engines
from dotenv import load_dotenv
import logging

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def deploy_security_orchestrator() -> None:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    location = os.environ.get("GOOGLE_CLOUD_LOCATION", "us-central1")
    staging_bucket = os.environ.get("GOOGLE_CLOUD_STAGING_BUCKET")

    if not all([project_id, staging_bucket]):
        raise ValueError("GOOGLE_CLOUD_PROJECT and GOOGLE_CLOUD_STAGING_BUCKET must be set.")

    vertexai.init(project=project_id, location=location, staging_bucket=staging_bucket)


    # Resource names of the three specialist agents — must be deployed first.
    # These are captured at deploy time and baked into the container.
    SPECIALIST_AGENT_MAP = {
        "iam_changes":  os.environ.get("GOOGLE_CLOUD_AGENT_ENGINE_ID_IAM_CHANGES"),
        "bucket_audit": os.environ.get("GOOGLE_CLOUD_AGENT_ENGINE_ID_BUCKET_AUDIT"),
        "remediation":  os.environ.get("GOOGLE_CLOUD_AGENT_ENGINE_ID_REMEDIATION"),
    }

    missing = [k for k, v in SPECIALIST_AGENT_MAP.items() if not v]
    if missing:
        raise ValueError(f"Missing specialist agent IDs for: {missing}")

    class SecurityOrchestrator:
        """
        Orchestrator agent for IT security operations.

        Receives a user query and routes it to the correct specialist:
          - iam_changes  → IamChangesAgent    (Cloud Audit Logs)
          - bucket_audit → BucketAuditAgent   (Cloud Storage IAM)
          - remediation  → RemediationAgent   (revoke IAM binding)

        The federated Google access_token is passed through so each specialist
        can call Google APIs on behalf of the authenticated user.
        """

        def set_up(self):
            self._user_id = "anonymous"
            self._access_token = None

            # Capture resource IDs at deploy time via closure — never pickled
            _agent_map = {
                "iam_changes":  SPECIALIST_AGENT_MAP["iam_changes"],
                "bucket_audit": SPECIALIST_AGENT_MAP["bucket_audit"],
                "sa_lookup":    SPECIALIST_AGENT_MAP["remediation"],  # same agent, read-only tool
                "remediation":  SPECIALIST_AGENT_MAP["remediation"],
            }

            def call_specialist_agent(agent_type: str, user_query: str) -> str:
                """
                Route a security query to the appropriate specialist agent.

                agent_type: Must be exactly one of:
                    'iam_changes'  — query Cloud Audit Logs for IAM policy changes
                    'bucket_audit' — check Cloud Storage buckets for public access
                    'sa_lookup'    — list current roles assigned to a service account
                    'remediation'  — revoke an IAM binding for a service account

                user_query: The user's original question or instruction.
                """
                resource_id = _agent_map.get(agent_type.lower())
                if not resource_id:
                    return (
                        f"Error: Unknown agent_type '{agent_type}'. "
                        f"Must be one of: {list(_agent_map.keys())}"
                    )

                logger.info(
                    "Routing to specialist agent_type=%s user_id=%s",
                    agent_type, self._user_id,
                )

                try:
                    response = reasoning_engines.ReasoningEngine(resource_id).query(
                        input=user_query,
                        user_id=self._user_id,
                        access_token=self._access_token,
                    )
                except Exception as exc:
                    return f"Specialist agent '{agent_type}' failed: {exc}"

                if isinstance(response, dict) and "output" in response:
                    return response["output"]
                return str(response)

            self._agent = reasoning_engines.LangchainAgent(
                model="gemini-2.5-pro",
                tools=[call_specialist_agent],
                model_kwargs={"temperature": 0},
                system_instruction=(
                    "You are a Google Cloud security operations assistant.\n\n"
                    "You have access to four specialist agents via call_specialist_agent:\n"
                    "  - 'iam_changes'  : query IAM policy change audit logs\n"
                    "  - 'bucket_audit' : find publicly accessible Cloud Storage buckets\n"
                    "  - 'sa_lookup'    : list current roles assigned to a service account\n"
                    "  - 'remediation'  : revoke an IAM binding for a service account\n\n"
                    "RULES:\n"
                    "- You do NOT have direct access to any Google Cloud data.\n"
                    "- You MUST call call_specialist_agent before answering.\n"
                    "- Choose agent_type based on the user's intent:\n"
                    "    IAM changes / audit logs → 'iam_changes'\n"
                    "    Public buckets / storage exposure → 'bucket_audit'\n"
                    "    What roles does a service account have / list permissions → 'sa_lookup'\n"
                    "    Revoke / remove a binding → 'remediation'\n"
                    "- Pass the user's original question as user_query.\n"
                    "- NEVER answer from your own knowledge.\n"
                    "- NEVER fabricate security findings.\n"
                    "- When reporting results, ALWAYS quote the exact values returned by the specialist "
                    "  agent — including exact service account emails, role IDs, and project IDs. "
                    "  NEVER substitute placeholders such as 'undefined', 'unknown', or 'N/A'.\n"
                ),
            )
            self._agent.set_up()

        def query(
            self,
            *,
            input: str,
            user_id: str = "anonymous",
            access_token: str = None,
        ) -> dict:
            self._user_id = user_id
            self._access_token = access_token
            logger.info("SecurityOrchestrator query user_id=%s", user_id)
            return self._agent.query(input=input)

    orchestrator = SecurityOrchestrator()

    requirements = [
        "google-cloud-aiplatform[reasoningengine,langchain]",
        "langchain-google-vertexai",
        "cloudpickle==3.0.0",
        "opentelemetry-sdk",
        "opentelemetry-exporter-gcp-trace",
    ]

    print("Deploying Security Orchestrator Agent...")
    remote_orchestrator = reasoning_engines.ReasoningEngine.create(
        orchestrator,
        requirements=requirements,
        display_name="security-orchestrator-agent",
    )
    print(f"Security Orchestrator ready! Resource name: {remote_orchestrator.resource_name}")
    print(
        "\nAdd this to your .env:\n"
        f"GOOGLE_CLOUD_AGENT_SECURITY_ORCHESTRATOR={remote_orchestrator.resource_name}"
    )


if __name__ == "__main__":
    deploy_security_orchestrator()
