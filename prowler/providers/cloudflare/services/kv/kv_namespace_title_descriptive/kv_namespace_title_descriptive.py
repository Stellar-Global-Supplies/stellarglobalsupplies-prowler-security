from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.kv.kv_client import kv_client


class kv_namespace_title_descriptive(Check):
    """Ensure KV namespaces have descriptive titles for auditability.

    KV namespaces with generic names like 'kv1', 'test', 'namespace1' make it
    difficult to determine their purpose, which Worker owns them, or whether they
    are safe to delete.  Descriptive titles improve operational hygiene and reduce
    the risk of accidental deletion or misuse of orphaned namespaces.
    """

    GENERIC_PATTERNS = [
        "kv1", "kv2", "kv3", "test", "temp", "tmp", "namespace",
        "default", "untitled", "new", "demo", "example",
    ]
    MIN_TITLE_LENGTH = 4

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for ns in kv_client.namespaces.values():
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=ns,
                resource_name=ns.title,
                resource_id=ns.id,
            )
            title_lower = ns.title.lower().strip()
            is_generic = (
                len(title_lower) < self.MIN_TITLE_LENGTH
                or any(title_lower == p or title_lower.startswith(p + "-") or title_lower.startswith(p + "_")
                       for p in self.GENERIC_PATTERNS)
            )
            if is_generic:
                report.status = "FAIL"
                report.status_extended = (
                    f"KV namespace '{ns.title}' has a generic or non-descriptive title. "
                    f"Rename it to reflect its purpose and owning service "
                    f"(e.g. 'stellarglobal-api-rate-limits')."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"KV namespace '{ns.title}' has a descriptive title."
                )
            findings.append(report)
        return findings
