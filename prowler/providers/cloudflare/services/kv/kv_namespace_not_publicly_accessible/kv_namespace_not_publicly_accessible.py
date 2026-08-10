from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.kv.kv_client import kv_client


class kv_namespace_not_publicly_accessible(Check):
    """Ensure KV namespaces are not inadvertently exposed.

    KV namespaces have no public HTTP endpoint — they are only accessible
    via a bound Worker.  This check inventories all KV namespaces and flags
    any whose title suggests they may be used as a cache/session store with
    user-controlled keys, which can introduce cache-poisoning or key-enumeration
    risks if the bound Worker does not sanitise input properly.

    Titles matching patterns like 'cache', 'session', 'public', or 'user'
    are flagged for review, as these are common patterns where insufficient
    key validation leads to data leakage between users.
    """

    SENSITIVE_PATTERNS = [
        "session", "auth", "token", "user", "cache", "public", "secret", "credential"
    ]

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for ns in kv_client.namespaces.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=ns,
                resource_name=ns.title,
                resource_id=ns.id,
            )
            title_lower = ns.title.lower()
            matched = [p for p in self.SENSITIVE_PATTERNS if p in title_lower]
            if matched:
                report.status = "FAIL"
                report.status_extended = (
                    f"KV namespace '{ns.title}' has a name suggesting it stores "
                    f"sensitive data ({', '.join(matched)}). Verify the bound Worker "
                    f"sanitises user-controlled keys to prevent cross-user data leakage."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"KV namespace '{ns.title}' does not have a name suggesting "
                    f"publicly accessible or sensitive data patterns."
                )
            findings.append(report)
        return findings
