from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.d1.d1_client import d1_client

# Cloudflare D1 does not expose a backup/export schedule API.
# The only way to back up D1 is via wrangler d1 export or the REST export endpoint.
# This check flags ALL databases as needing manual backup verification,
# since there is no automated backup feature and no API to confirm backup status.


class d1_database_backup_configured(Check):
    """Ensure D1 databases have an external backup strategy.

    Cloudflare D1 does not provide automated backups or point-in-time recovery.
    Data loss due to accidental deletion, a buggy Worker migration, or a
    Cloudflare incident cannot be recovered without a customer-managed export.
    This check flags all D1 databases as requiring operator confirmation that
    a backup process (e.g. scheduled wrangler export to R2) is in place.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for db in d1_client.databases.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=db,
                resource_name=db.name,
                resource_id=db.id,
            )
            # D1 has no backup API — all databases need manual confirmation
            report.status = "FAIL"
            report.status_extended = (
                f"D1 database '{db.name}' ({db.id}) has no automated backup. "
                f"Cloudflare D1 does not provide built-in backups. "
                f"Implement a scheduled export (e.g. wrangler d1 export piped to R2) "
                f"to protect against data loss."
            )
            findings.append(report)
        return findings
