"""
json_results.py  –  Prowler ``json-results`` output format
===========================================================

Exports **every** executed check result (PASS, FAIL, MANUAL, MUTED …) as a
flat JSON array.  Unlike the stock Prowler exporters this formatter never
filters findings; it serialises the full ``Finding`` object that Prowler
already constructs internally.

Output file names:
    ``<output-directory>/<output-filename>.results.json``

Usage:
    prowler aws         --output-formats json-results --output-directory ./output
    prowler cloudflare  --output-formats json-results --output-directory ./output

The resulting file is designed for direct ingestion into a Cloudflare Worker /
D1 pipeline to power compliance dashboards, posture scores, and historical
trend reporting.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from prowler.lib.logger import logger
from prowler.lib.outputs.finding import Finding
from prowler.lib.outputs.output import Output


# ---------------------------------------------------------------------------
# Schema version – bump this whenever the JSON shape changes breaking-ly so
# that downstream consumers (Workers, D1 loaders) can gate on it.
# ---------------------------------------------------------------------------
_SCHEMA_VERSION = "1.0.0"


class JSONResults(Output):
    """Output subclass that serialises *all* findings to a JSON array.

    Every ``Finding`` object produced by the scan engine is converted to a
    flat dictionary and appended to ``self._data``.  When
    ``batch_write_data_to_file`` is called the list is serialised as a
    JSON array and written to the configured file path.

    Attributes:
        _data:            Accumulated list of serialised finding dicts.
        _file_descriptor: File handle opened by the parent ``Output`` class.
        _file_extension:  Always ``.results.json``.
    """

    # ------------------------------------------------------------------
    # Init  (overridden so the file is ALWAYS created, even with zero
    # findings — the parent Output.__init__ skips transform and file
    # creation when the findings list is falsy, which would leave the
    # output file empty/absent for no-resource scans).
    # ------------------------------------------------------------------

    def __init__(
        self,
        findings: List[Finding],
        file_path: Optional[str] = None,
        file_extension: str = "",
        from_cli: bool = True,
    ) -> None:
        """Initialise the exporter and always create the output file.

        Unlike the parent ``Output.__init__`` (which returns early when
        ``findings`` is falsy), this override always:

        * runs ``transform`` (a no-op for an empty list), and
        * creates the file descriptor.

        This guarantees ``batch_write_data_to_file`` always has a valid
        file handle to write to, so a zero-resource scan still produces a
        parseable ``{"schema_version": ..., "total": 0, "results": []}``
        envelope instead of a 0-byte / missing file.

        Parameters
        ----------
        findings:
            List of ``Finding`` objects (may be empty).
        file_path:
            Path to the output file.
        file_extension:
            Optional file-extension override.
        from_cli:
            Whether the exporter is invoked from the CLI.
        """
        self._data: List[Dict[str, Any]] = []
        self.close_file = False
        self.file_path = file_path
        self._file_descriptor = None
        self._from_cli = from_cli

        if not file_extension and file_path:
            from pathlib import Path

            self._file_extension = "".join(Path(file_path).suffixes)
        if file_extension:
            self._file_extension = file_extension
            self.file_path = f"{file_path}{self.file_extension}"

        # Always transform — even when findings is empty — so the output
        # file is always generated.
        self.transform(findings)
        if not self._file_descriptor and file_path:
            self.create_file_descriptor(self.file_path)

    # ------------------------------------------------------------------
    # Transform  (called by __init__)
    # ------------------------------------------------------------------

    def transform(self, findings: List[Finding]) -> None:
        """Convert each Finding into a serialisable dict and store it.

        Parameters
        ----------
        findings:
            List of ``Finding`` objects produced by ``Finding.generate_output``.
            May contain results with any status value; **no filtering is applied**.
        """
        try:
            for finding in findings:
                self._data.append(_finding_to_dict(finding))
        except Exception as exc:
            logger.error(
                f"{exc.__class__.__name__}[{exc.__traceback__.tb_lineno}]: {exc}"
            )

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def batch_write_data_to_file(self) -> None:
        """Write ``self._data`` as a JSON array to ``self._file_descriptor``.

        The file is always written (even when ``self._data`` is empty) so that
        downstream consumers receive a valid, parseable document.  The output
        format is:

        .. code-block:: json

            {
              "schema_version": "1.0.0",
              "total": 42,
              "results": [ ... ]
            }

        An empty scan produces:

        .. code-block:: json

            {
              "schema_version": "1.0.0",
              "total": 0,
              "results": []
            }
        """
        try:
            fd = getattr(self, "_file_descriptor", None)
            if fd is None or fd.closed:
                return

            payload: Dict[str, Any] = {
                "schema_version": _SCHEMA_VERSION,
                "total": len(self._data),
                "results": self._data,
            }

            fd.write(json.dumps(payload, default=_json_default, indent=2))
            fd.write("\n")

            if self.close_file or self._from_cli:
                fd.close()

        except Exception as exc:
            logger.error(
                f"{exc.__class__.__name__}[{exc.__traceback__.tb_lineno}]: {exc}"
            )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _finding_to_dict(finding: Finding) -> Dict[str, Any]:
    """Flatten a ``Finding`` object into a serialisable dictionary.

    All metadata available on the ``Finding`` model is included.  The schema
    deliberately mirrors the field names requested by the CSPM platform spec
    while also exposing the raw metadata block so future consumers can access
    any field that may be added to ``CheckMetadata`` without requiring an
    exporter update.

    Parameters
    ----------
    finding:
        A fully-populated ``Finding`` instance.

    Returns
    -------
    dict
        Flat, JSON-serialisable representation of the finding.
    """
    meta = finding.metadata

    # Remediation block (nested → flat for D1/SQL ease-of-use)
    remediation_text: str = ""
    remediation_url: str = ""
    remediation_cli: str = ""
    remediation_terraform: str = ""
    remediation_native_iac: str = ""
    remediation_other: str = ""
    try:
        remediation_text = meta.Remediation.Recommendation.Text or ""
        remediation_url = meta.Remediation.Recommendation.Url or ""
        remediation_cli = meta.Remediation.Code.CLI or ""
        remediation_terraform = meta.Remediation.Code.Terraform or ""
        remediation_native_iac = meta.Remediation.Code.NativeIaC or ""
        remediation_other = meta.Remediation.Code.Other or ""
    except AttributeError:
        pass

    # Compliance frameworks → list of "FRAMEWORK|REQUIREMENT" strings
    compliance_frameworks: List[str] = []
    try:
        for framework, requirements in (finding.compliance or {}).items():
            if isinstance(requirements, list):
                for req in requirements:
                    compliance_frameworks.append(f"{framework}|{req}")
            else:
                compliance_frameworks.append(f"{framework}|{requirements}")
    except Exception:
        pass

    # Determine effective status string, including MUTED pseudo-status
    status_value: str = _status_value(finding)

    record: Dict[str, Any] = {
        # ── Identity ────────────────────────────────────────────────────
        "finding_uid": finding.uid,
        "provider": meta.Provider,
        "auth_method": finding.auth_method,
        # ── Account / Tenant ────────────────────────────────────────────
        "account_uid": finding.account_uid,
        "account_name": finding.account_name,
        "account_email": finding.account_email,
        "account_organization_uid": finding.account_organization_uid,
        "account_organization_name": finding.account_organization_name,
        "account_ou_uid": finding.account_ou_uid,
        "account_ou_name": finding.account_ou_name,
        "account_tags": finding.account_tags or {},
        "partition": finding.partition,
        # ── Location ────────────────────────────────────────────────────
        "region": finding.region,
        # ── Resource ────────────────────────────────────────────────────
        "resource_uid": finding.resource_uid,
        "resource_name": finding.resource_name,
        "resource_type": meta.ResourceType,
        "resource_details": finding.resource_details,
        "resource_tags": finding.resource_tags or {},
        "resource_metadata": finding.resource_metadata or {},
        # ── Check ───────────────────────────────────────────────────────
        "check_id": meta.CheckID,
        "check_title": meta.CheckTitle,
        "check_type": meta.CheckType or [],
        "check_description": meta.Description,
        "service_name": meta.ServiceName,
        "subservice_name": meta.SubServiceName,
        # ── Result ──────────────────────────────────────────────────────
        "status": status_value,
        "status_extended": finding.status_extended,
        "muted": finding.muted,
        # ── Risk / Severity ─────────────────────────────────────────────
        "severity": _enum_value(meta.Severity),
        "risk": meta.Risk,
        # ── Compliance ──────────────────────────────────────────────────
        "compliance": finding.compliance or {},
        "compliance_frameworks": compliance_frameworks,
        "categories": meta.Categories or [],
        "depends_on": meta.DependsOn or [],
        "related_to": meta.RelatedTo or [],
        # ── Remediation ─────────────────────────────────────────────────
        "remediation": {
            "recommendation_text": remediation_text,
            "recommendation_url": remediation_url,
            "code_cli": remediation_cli,
            "code_terraform": remediation_terraform,
            "code_native_iac": remediation_native_iac,
            "code_other": remediation_other,
        },
        # ── Documentation ───────────────────────────────────────────────
        "documentation_url": meta.RelatedUrl,
        "notes": meta.Notes,
        "additional_urls": meta.AdditionalURLs or [],
        # ── Timing ──────────────────────────────────────────────────────
        "timestamp": _normalise_timestamp(finding.timestamp),
        # ── Prowler meta ────────────────────────────────────────────────
        "prowler_version": finding.prowler_version,
        # Full raw metadata dict – allows downstream to access any new fields
        # added to CheckMetadata without requiring an exporter update.
        "raw_metadata": finding.get_metadata(),
    }

    return record


def _status_value(finding: Finding) -> str:
    """Return the canonical status string for a finding.

    If the finding is muted the status is returned as ``"MUTED"`` so that
    dashboards can track muted results separately without losing the underlying
    pass/fail information (which is preserved in ``status_extended``).

    Parameters
    ----------
    finding:
        A ``Finding`` instance.

    Returns
    -------
    str
        One of: ``PASS``, ``FAIL``, ``MANUAL``, ``MUTED``, or the raw enum
        value for any other status encountered.
    """
    if finding.muted:
        return "MUTED"
    return _enum_value(finding.status)


def _enum_value(obj: Any) -> Any:
    """Return ``.value`` if *obj* is an enum, otherwise return *obj* unchanged."""
    return obj.value if hasattr(obj, "value") else obj


def _normalise_timestamp(ts: Any) -> Optional[str]:
    """Normalise a timestamp to an ISO-8601 string for JSON output.

    Prowler stores timestamps as either a ``datetime`` object or a Unix
    integer depending on the ``--unix-timestamp`` flag.  Both are converted
    to an ISO-8601 string so that D1 / SQL consumers can use standard date
    functions without branch logic.

    Parameters
    ----------
    ts:
        Timestamp value from ``Finding.timestamp``.

    Returns
    -------
    str or None
        ISO-8601 string, e.g. ``"2025-01-15T10:30:00"``, or ``None`` if the
        value cannot be interpreted.
    """
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts.isoformat()
    if isinstance(ts, (int, float)):
        try:
            return datetime.utcfromtimestamp(ts).isoformat()
        except (OSError, OverflowError, ValueError):
            return str(ts)
    return str(ts)


def _json_default(obj: Any) -> Any:
    """JSON serialisation fallback for non-standard types.

    Parameters
    ----------
    obj:
        Object that the standard JSON encoder cannot handle.

    Returns
    -------
    str
        String representation used in the JSON output.

    Raises
    ------
    TypeError
        Re-raised when the object type is completely unknown.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "value"):
        return obj.value  # Enum → its primitive value
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    raise TypeError(f"Object of type {type(obj)} is not JSON serialisable")