from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.workers.workers_client import workers_client


class workers_script_usage_model_standard(Check):
    """Ensure Worker scripts use the Standard usage model.

    The 'bundled' (legacy) usage model has lower CPU limits and no isolation
    guarantees between requests.  Standard and Unbound models provide proper
    per-request isolation and higher limits, reducing the risk of timing
    side-channel attacks and resource exhaustion.
    """

    RECOMMENDED = {"standard", "unbound"}

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for script in workers_client.scripts.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=script,
                resource_name=script.id,
                resource_id=script.id,
            )
            model = (script.usage_model or "").lower()
            if model in self.RECOMMENDED:
                report.status = "PASS"
                report.status_extended = (
                    f"Worker '{script.id}' uses usage model '{model}'."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Worker '{script.id}' uses usage model '{model or 'unknown'}'. "
                    f"Upgrade to 'standard' for better isolation and higher CPU limits."
                )
            findings.append(report)
        return findings
