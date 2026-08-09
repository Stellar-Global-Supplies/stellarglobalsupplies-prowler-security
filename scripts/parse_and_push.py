#!/usr/bin/env python3
"""
parse_and_push.py
=================

Parses a Prowler json-results output file and uploads findings to the
Cloudflare Worker ingest endpoint in batched POST requests.

Supports both output formats:
  - json-results  flat JSON array []          (auto-detected via .results.json)
  - json-results  envelope {schema_version, total, results:[]}
  - ocsf          OCSF detection-finding format

Usage:
    python3 scripts/parse_and_push.py \
        --file ./output/aws-findings.results.json \
        --provider aws \
        --url "$CF_WORKER_INGEST_URL" \
        --token "$CF_WORKER_INGEST_TOKEN"
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
import uuid

SEVERITY_MAP = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
}


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def _empty_scan(provider: str) -> dict:
    """Return a zero-finding scan_run record so the dashboard always sees a run."""
    return {
        "id": str(uuid.uuid4()),
        "provider": provider,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": 0.0,
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }


def parse_json_results(filepath: str, provider: str):
    """Parse a Prowler json-results output file.

    Handles two variants that may come from different versions of the exporter:
      - Flat array:   [ { ... }, { ... } ]
      - Envelope:     { "schema_version": "1.0.0", "total": N, "results": [...] }

    When the file is missing or empty/invalid JSON we still return a scan_run
    record (with zero findings) so the Worker records that a scan ran and the
    dashboard always shows the provider — instead of silently skipping it.
    """
    try:
        with open(filepath, "r") as f:
            content = f.read().strip()
    except FileNotFoundError:
        print(f"[warn] File not found: {filepath} — recording zero-finding scan.")
        return _empty_scan(provider), [], [], []

    if not content:
        print(f"[warn] File is empty: {filepath} — recording zero-finding scan.")
        return _empty_scan(provider), [], [], []

    try:
        raw = json.loads(content)
    except json.JSONDecodeError as e:
        print(f"[warn] Invalid JSON in {filepath}: {e} — recording zero-finding scan.")
        return _empty_scan(provider), [], [], []

    # Handle both flat array and envelope formats
    if isinstance(raw, list):
        findings = raw
    elif isinstance(raw, dict):
        # Envelope format: { "schema_version": ..., "total": ..., "results": [...] }
        findings = raw.get("results", raw.get("findings", []))
    else:
        print(f"[warn] Unexpected JSON structure in {filepath} — recording zero-finding scan.")
        return _empty_scan(provider), [], [], []

    print(f"[info] Loaded {len(findings)} records from {filepath}")

    parsed = []
    resources = {}

    # Derive a stable scan_id from the first finding's scan_id field if present,
    # otherwise generate a fresh UUID. This keeps all findings from one scan
    # grouped under the same scan_run row.
    scan_id = (
        findings[0].get("scan_id", str(uuid.uuid4()))
        if findings
        else str(uuid.uuid4())
    )

    counts = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for f in findings:
        # ── Status ──────────────────────────────────────────────────────────
        # status_code is the raw Prowler value: PASS / FAIL / MANUAL / MUTED
        # We map PASS → PASS, everything else → FAIL for the D1 findings table
        # so that dashboard queries "WHERE status = 'FAIL'" work correctly.
        raw_status = (f.get("status_code") or f.get("status") or "FAIL").upper()
        status = "PASS" if raw_status == "PASS" else "FAIL"
        muted = f.get("muted", False) or raw_status == "MUTED"

        # ── Severity ────────────────────────────────────────────────────────
        sev = (f.get("severity") or "low").lower()
        if sev not in SEVERITY_MAP:
            sev = "low"

        # ── Resource fields ─────────────────────────────────────────────────
        uid = f.get("resource_uid") or ""
        svc = (f.get("service") or f.get("service_name") or "").lower()
        region = f.get("region") or "global"
        resource_name = f.get("resource_name") or uid
        resource_type = f.get("resource_type") or ""

        # ── Description ─────────────────────────────────────────────────────
        # Combine check_description + status_extended for maximum context
        check_description = f.get("check_description") or f.get("description") or ""
        status_extended = f.get("status_extended") or ""
        if status_extended:
            description = (
                f"{check_description} — {status_extended}"
                if check_description
                else status_extended
            )
        else:
            description = check_description

        # ── Remediation ─────────────────────────────────────────────────────
        # Exporter writes: remediation.recommendation_text / recommendation_url
        remediation = ""
        remediation_data = f.get("remediation") or {}
        if isinstance(remediation_data, dict):
            rec_text = remediation_data.get("recommendation_text") or ""
            rec_url = remediation_data.get("recommendation_url") or ""
            if rec_text:
                remediation = f"{rec_text}\n{rec_url}".strip() if rec_url else rec_text
        elif isinstance(remediation_data, str):
            remediation = remediation_data

        # ── Timestamp ───────────────────────────────────────────────────────
        scanned_at = f.get("timestamp") or datetime.now(timezone.utc).isoformat()

        parsed.append({
            "id": str(uuid.uuid4()),
            "scan_run_id": scan_id,
            "provider": provider,
            "service": svc,
            "check_id": f.get("check_id") or "",
            "check_title": f.get("check_title") or "",
            "status": status,
            "severity": sev,
            "resource_uid": uid,
            "resource_name": resource_name,
            "resource_type": resource_type,
            "region": region,
            "description": description,
            "remediation": remediation,
            "scanned_at": scanned_at,
        })

        # ── Counts ──────────────────────────────────────────────────────────
        counts["total"] += 1
        if status == "PASS":
            counts["passed"] += 1
        else:
            counts["failed"] += 1
            if sev in counts:
                counts[sev] += 1

        # ── Resource dedup ───────────────────────────────────────────────────
        if uid and svc:
            rid = f"{provider}:{svc}:{uid}"
            if rid not in resources:
                resources[rid] = {
                    "id": rid,
                    "provider": provider,
                    "service": svc,
                    "resource_uid": uid,
                    "resource_name": resource_name,
                    "resource_type": resource_type,
                    "region": region,
                    "risk_score": SEVERITY_MAP.get(sev, 0),
                }

    score = (
        round((counts["passed"] / counts["total"]) * 100, 1)
        if counts["total"] > 0
        else 0.0
    )

    scan = {
        "id": scan_id,
        "provider": provider,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        **counts,
    }

    print(
        f"[info] Scan {scan_id[:8]}… | "
        f"total={counts['total']} passed={counts['passed']} failed={counts['failed']} "
        f"score={score}%"
    )
    return scan, parsed, list(resources.values()), []


def parse_ocsf(filepath: str, provider: str):
    """Parse a Prowler OCSF (json-ocsf) output file."""
    try:
        with open(filepath, "r") as f:
            content = f.read().strip()
    except FileNotFoundError:
        print(f"[warn] File not found: {filepath} — recording zero-finding scan.")
        return _empty_scan(provider), [], [], []

    if not content:
        print(f"[warn] File is empty: {filepath} — recording zero-finding scan.")
        return _empty_scan(provider), [], [], []

    try:
        raw = json.loads(content)
    except json.JSONDecodeError as e:
        print(f"[warn] Invalid JSON in {filepath}: {e} — recording zero-finding scan.")
        return _empty_scan(provider), [], [], []

    findings = raw if isinstance(raw, list) else raw.get("findings", [])
    parsed = []
    resources = {}
    scan_id = str(uuid.uuid4())
    counts = {
        "total": 0, "passed": 0, "failed": 0,
        "critical": 0, "high": 0, "medium": 0, "low": 0,
    }

    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if sev not in SEVERITY_MAP:
            sev = "low"
        status_code = f.get("status_code") or "FAIL"
        status = "PASS" if status_code in ("PASS", "pass") else "FAIL"
        res = (f.get("resources") or [{}])[0] if f.get("resources") else {}
        uid = res.get("uid") or res.get("id") or ""
        svc = (
            (f.get("cloud") or {}).get("service", {}).get("name")
            or f.get("service")
            or ""
        ).lower()
        region = (f.get("cloud") or {}).get("region") or "global"

        parsed.append({
            "id": str(uuid.uuid4()),
            "scan_run_id": scan_id,
            "provider": provider,
            "service": svc,
            "check_id": f.get("check_id") or f.get("type_uid") or "",
            "check_title": f.get("check_title") or f.get("message") or "",
            "status": status,
            "severity": sev,
            "resource_uid": uid,
            "resource_name": res.get("name") or uid,
            "resource_type": res.get("type") or "",
            "region": region,
            "description": f.get("description") or "",
            "remediation": "",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        })

        counts["total"] += 1
        if status == "PASS":
            counts["passed"] += 1
        else:
            counts["failed"] += 1
            if sev in counts:
                counts[sev] += 1

        if uid and svc:
            rid = f"{provider}:{svc}:{uid}"
            resources.setdefault(rid, {
                "id": rid, "provider": provider, "service": svc,
                "resource_uid": uid, "resource_name": res.get("name") or uid,
                "resource_type": res.get("type") or "", "region": region,
                "risk_score": SEVERITY_MAP.get(sev, 0),
            })

    scan = {
        "id": scan_id,
        "provider": provider,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": round((counts["passed"] / counts["total"]) * 100, 1) if counts["total"] else 0,
        **counts,
    }
    return scan, parsed, list(resources.values()), []


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def post(url: str, token: str, body: dict, retries: int = 3) -> bool:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "ProwlerUploader/2.0",
            "Accept": "application/json",
        },
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                print(f"[ok] HTTP {r.status} ({len(data):,} bytes)")
                return True
        except urllib.error.HTTPError as e:
            error_body = e.read().decode(errors="ignore")
            print(f"[warn] HTTP {e.code}: {error_body}")
            if attempt == retries - 1:
                print(f"[error] Failed after {retries} attempts")
                return False
            wait = 2 ** attempt
            print(f"[retry] Waiting {wait}s…")
            time.sleep(wait)
        except urllib.error.URLError as e:
            print(f"[error] Network error: {e.reason}")
            if attempt == retries - 1:
                return False
            time.sleep(2 ** attempt)
    return False


def push(url: str, token: str, scan: dict, findings: list,
         resources: list, edges: list) -> bool:
    """Upload scan + findings to the Worker in batches of 50.

    If there are zero findings we still send one request containing the
    scan_run record so the Worker records that the scan ran (posture score
    history, last-seen timestamps, etc.).
    """
    CHUNK = 50

    # Always send at least one batch so the scan_run row is written even
    # when there are zero findings.
    if not findings:
        payload = {
            "scan_run": scan,
            "findings": [],
            "resources": resources,
            "edges": edges,
        }
        print("[info] Zero findings — sending scan_run record only")
        return post(url, token, payload)

    total_batches = (len(findings) + CHUNK - 1) // CHUNK
    print(f"[info] Uploading {len(findings)} findings in {total_batches} batch(es)")

    failed_batches = []
    for idx in range(total_batches):
        batch = findings[idx * CHUNK:(idx + 1) * CHUNK]
        is_last = idx == total_batches - 1
        payload = {
            "scan_run": scan if idx == 0 else {"id": scan["id"]},
            "findings": batch,
            "resources": resources if is_last else [],
            "edges": edges if is_last else [],
        }
        print(
            f"[batch {idx + 1}/{total_batches}] "
            f"findings={len(batch)} "
            f"resources={len(payload['resources'])} "
            f"edges={len(payload['edges'])}"
        )
        if not post(url, token, payload):
            failed_batches.append(idx + 1)

    if failed_batches:
        print(f"[summary] Failed batches: {failed_batches} "
              f"({total_batches - len(failed_batches)}/{total_batches} succeeded)")
        return False

    print(f"[success] All {total_batches} batch(es) uploaded")
    return True


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Upload Prowler findings to a Cloudflare Worker / D1 pipeline."
    )
    ap.add_argument("--file",     required=True,  help="Path to the Prowler output file")
    ap.add_argument("--provider", required=True,  help="Cloud provider: aws or cloudflare")
    ap.add_argument("--url",      required=True,  help="Worker ingest URL")
    ap.add_argument("--token",    required=True,  help="Bearer token for the Worker")
    ap.add_argument(
        "--format", default="auto",
        choices=["auto", "ocsf", "json-results"],
        help="Input format (default: auto-detect from file extension)",
    )
    a = ap.parse_args()

    # Auto-detect format from file extension
    if a.format == "auto":
        if a.file.endswith(".results.json"):
            fmt = "json-results"
        elif a.file.endswith(".ocsf.json") or a.file.endswith(".json"):
            fmt = "ocsf"
        else:
            print(f"[error] Cannot auto-detect format for {a.file} — use --format")
            sys.exit(1)
    else:
        fmt = a.format

    print(f"[info] Format={fmt}  Provider={a.provider}  File={a.file}")

    if fmt == "json-results":
        scan, findings, resources, edges = parse_json_results(a.file, a.provider)
    else:
        scan, findings, resources, edges = parse_ocsf(a.file, a.provider)

    # scan is always set (at minimum a zero-finding scan_run so the dashboard
    # records that a scan ran for this provider).
    if scan is None:
        # Should not happen — kept as a safety net.
        print("[skip] Parser returned no scan record — exiting cleanly.")
        sys.exit(0)

    ok = push(a.url, a.token, scan, findings, resources, edges)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()