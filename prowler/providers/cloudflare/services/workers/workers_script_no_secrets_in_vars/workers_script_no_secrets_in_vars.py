from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.workers.workers_client import workers_client


class workers_script_no_secrets_in_vars(Check):
    """Ensure Worker scripts do not expose secrets as plain-text env vars.

    Plain-text environment variable bindings are visible to anyone with
    dashboard access and are not encrypted at rest.  Sensitive values
    (tokens, passwords, API keys, etc.) should always use Secret bindings.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for script in workers_client.scripts.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=script,
                resource_name=script.id,
                resource_id=script.id,
            )
            if script.has_plaintext_secrets:
                bad_vars = [
                    v for v in script.plain_env_vars
                    if any(p in v.lower() for p in workers_client.SECRET_PATTERNS)
                ]
                report.status = "FAIL"
                report.status_extended = (
                    f"Worker '{script.id}' has plain-text env vars with "
                    f"secret-looking names: {', '.join(bad_vars)}. "
                    f"Move these to Secret bindings."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Worker '{script.id}' has no plain-text env vars "
                    f"with secret-looking names."
                )
            findings.append(report)
        return findings
