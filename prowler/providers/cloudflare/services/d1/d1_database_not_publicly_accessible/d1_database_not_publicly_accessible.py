from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.d1.d1_client import d1_client


class d1_database_not_publicly_accessible(Check):
    """Ensure D1 databases are only accessible via bound Workers/Pages.

    D1 databases can only be accessed through a bound Worker or Pages Function —
    they have no public HTTP API endpoint.  This check verifies the database
    exists and is properly named, flagging databases whose names suggest they
    may be used in an overly permissive pattern (e.g. 'public-*' or 'test-*'
    databases left in production accounts that widen the blast radius).

    Primary value: inventory check — surfaces all D1 databases so operators
    can confirm each one is bound to an appropriate Worker and not a forgotten
    test database with sensitive data.
    """

    # Names that suggest a database shouldn't be in a production account
    RISKY_PREFIXES = ("public-", "test-", "dev-", "tmp-", "temp-", "demo-")

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for db in d1_client.databases.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=db,
                resource_name=db.name,
                resource_id=db.id,
            )
            name_lower = db.name.lower()
            if any(name_lower.startswith(p) for p in self.RISKY_PREFIXES):
                report.status = "FAIL"
                report.status_extended = (
                    f"D1 database '{db.name}' has a name suggesting it is a "
                    f"test/development/public database present in a production account. "
                    f"Verify it is intentional and contains no sensitive data."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"D1 database '{db.name}' is present in the account. "
                    f"D1 databases are only accessible via bound Workers — "
                    f"no public HTTP endpoint exists."
                )
            findings.append(report)
        return findings
