from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.pages.pages_client import pages_client


class pages_project_source_connected(Check):
    """Ensure Pages projects are deployed from a connected Git source.

    Projects deployed via direct upload (drag-and-drop or Wrangler) bypass
    Git history, code review, and CI/CD gates.  Connecting to a GitHub or
    GitLab repository ensures every deployment is traceable, reviewable, and
    can be rolled back through version control.
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
            if project.source_connected:
                report.status = "PASS"
                report.status_extended = (
                    f"Pages project '{project.name}' is connected to a "
                    f"{project.source_type or 'git'} repository."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Pages project '{project.name}' uses direct upload (no Git "
                    f"source connected). Connect a GitHub or GitLab repository to "
                    f"enable audit trail, code review, and rollback."
                )
            findings.append(report)
        return findings
