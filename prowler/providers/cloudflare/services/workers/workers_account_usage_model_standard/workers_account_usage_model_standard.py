from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.workers.workers_client import workers_client


class workers_account_usage_model_standard(Check):
    """Ensure the account-level default Workers usage model is Standard.

    New scripts inherit the account default.  If the default is 'bundled',
    newly deployed scripts may silently run with legacy resource limits and
    weaker isolation until explicitly overridden per-script.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        settings = workers_client.account_settings
        if not settings:
            return findings

        # Use a synthetic resource object
        class _Res:
            id = "account"
            name = "account"
            resource = {}
            resource_name = "account"
            resource_id = "account"
            tags = []

        report = CheckReportCloudflare(
            metadata=self.metadata(),
            resource=_Res(),
            resource_name="account-default",
            resource_id="account-default",
        )
        model = (settings.default_usage_model or "").lower()
        if model in ("standard", "unbound", ""):
            report.status = "PASS"
            report.status_extended = (
                f"Account default Workers usage model is '{model or 'standard (implicit)'}'."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                f"Account default Workers usage model is '{model}'. "
                f"Set to 'standard' so new scripts inherit safe defaults."
            )
        findings.append(report)
        return findings
