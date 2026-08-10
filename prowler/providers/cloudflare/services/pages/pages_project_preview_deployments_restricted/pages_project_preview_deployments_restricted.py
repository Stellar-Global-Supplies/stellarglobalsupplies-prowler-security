from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.pages.pages_client import pages_client


class pages_project_preview_deployments_restricted(Check):
    """Ensure Pages preview deployments are disabled or restricted.

    By default, every branch push creates a publicly accessible preview URL
    at a *.pages.dev subdomain.  In production projects this can inadvertently
    expose in-progress features, staging credentials, or internal tooling to
    anyone who discovers the URL.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for project in pages_client.projects.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=project,
                resource_name=project.name,
                resource_id=project.id,
            )
            if not project.preview_deployments_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Pages project '{project.name}' has preview deployments disabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Pages project '{project.name}' has preview deployments enabled "
                    f"(all branch pushes create a public *.pages.dev URL). "
                    f"Disable or restrict preview deployments in project settings."
                )
            findings.append(report)
        return findings
