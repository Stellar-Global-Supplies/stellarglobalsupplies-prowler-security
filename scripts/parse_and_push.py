#!/usr/bin/env python3
"""
Parses Prowler OCSF JSON output and pushes findings to the CF Worker ingest endpoint.
Builds graph edges from resource relationships for the attack path visualization.
"""

import argparse
import json
import uuid
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

SEVERITY_MAP = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

ATTACK_RELATIONSHIPS = {
    ("s3", "iam"):            ("grants access to", "high"),
    ("iam", "ec2"):           ("can assume role on", "critical"),
    ("iam", "cloudflare"):    ("manages", "high"),
    ("cloudflare", "dns"):    ("controls zone for", "medium"),
    ("cloudflare", "worker"): ("deploys to", "high"),
    ("cloudflare", "d1"):     ("has binding to", "high"),
    ("cloudflare", "kv"):     ("has binding to", "medium"),
    ("cloudflare", "access"): ("protects via", "low"),
    ("s3", "cloudflare"):     ("serves assets through", "medium"),
}

def parse_ocsf(filepath: str, provider: str):
    try:
        with open(filepath, "r") as f:
            raw = json.load(f)
    except FileNotFoundError:
        print(f"[warn] File not found: {filepath}, skipping.")
        return None, [], []

    findings = raw if isinstance(raw, list) else raw.get("findings", [])

    parsed_findings = []
    resources = {}
    scan_run_id = str(uuid.uuid4())
    counts = {"total": 0, "passed": 0, "failed": 0,
              "critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings:
        severity = (f.get("severity", "low") or "low").lower()
        status_id = f.get("status_code", "FAIL")
        status = "PASS" if status_id in ("PASS", "pass") else "FAIL"

        resource = f.get("resources", [{}])[0] if f.get("resources") else {}
        resource_uid = resource.get("uid", "") or resource.get("id", "")
        resource_name = resource.get("name", resource_uid)
        resource_type = resource.get("type", "")
        service = f.get("cloud", {}).get("service", {}).get("name", "") or \
                  f.get("service", "") or ""

        finding_id = str(uuid.uuid4())
        parsed_findings.append({
            "id": finding_id,
            "scan_run_id": scan_run_id,
            "provider": provider,
            "service": service.lower(),
            "check_id": f.get("check_id", f.get("type_uid", "")),
            "check_title": f.get("check_title", f.get("message", "")),
            "status": status,
            "severity": severity,
            "resource_uid": resource_uid,
            "resource_name": resource_name,
            "resource_type": resource_type,
            "region": f.get("cloud", {}).get("region", "global"),
            "description": f.get("description", f.get("finding_info", {}).get("desc", "")),
            "remediation": f.get("remediation", {}).get("recommendation", {}).get("text", "")
                           if isinstance(f.get("remediation"), dict) else "",
        })

        counts["total"] += 1
        if status == "PASS":
            counts["passed"] += 1
        else:
            counts["failed"] += 1
            if severity in counts:
                counts[severity] += 1

        # build resource map for graph edges
        if resource_uid and service:
            r_id = f"{provider}:{service}:{resource_uid}"
            if r_id not in resources:
                risk = SEVERITY_MAP.get(severity, 0) if status == "FAIL" else 0
                resources[r_id] = {
                    "id": r_id,
                    "provider": provider,
                    "service": service.lower(),
                    "resource_type": resource_type,
                    "resource_uid": resource_uid,
                    "resource_name": resource_name,
                    "region": f.get("cloud", {}).get("region", "global"),
                    "risk_score": risk,
                }

    score = round((counts["passed"] / counts["total"]) * 100, 1) if counts["total"] > 0 else 0

    scan_run = {
        "id": scan_run_id,
        "provider": provider,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        **counts,
    }

    # Build attack path edges
    edges = []
    resource_list = list(resources.values())
    seen_edges = set()
    for i, src in enumerate(resource_list):
        for tgt in resource_list[i + 1:]:
            key = (src["service"], tgt["service"])
            rel = ATTACK_RELATIONSHIPS.get(key) or ATTACK_RELATIONSHIPS.get((tgt["service"], src["service"]))
            if rel and (src["id"], tgt["id"]) not in seen_edges:
                edges.append({
                    "id": str(uuid.uuid4()),
                    "source_id": src["id"],
                    "target_id": tgt["id"],
                    "source_label": src["resource_name"] or src["service"],
                    "target_label": tgt["resource_name"] or tgt["service"],
                    "relationship": rel[0],
                    "severity": rel[1],
                })
                seen_edges.add((src["id"], tgt["id"]))

    return scan_run, parsed_findings, list(resources.values()), edges


def push(url: str, token: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            print(f"[ok] {resp.status} — pushed {len(payload.get('findings', []))} findings")
    except urllib.error.HTTPError as e:
        print(f"[error] HTTP {e.code}: {e.read().decode()}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token", required=True)
    args = parser.parse_args()

    scan_run, findings, resources, edges = parse_ocsf(args.file, args.provider)
    if scan_run is None:
        print("[skip] No findings file, exiting cleanly.")
        sys.exit(0)

    push(args.url, args.token, {
        "scan_run": scan_run,
        "findings": findings,
        "resources": resources,
        "edges": edges,
    })


if __name__ == "__main__":
    main()
