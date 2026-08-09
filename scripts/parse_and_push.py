#!/usr/bin/env python3
"""
Chunked uploader for Prowler OCSF findings.

Drop-in replacement for parse_and_push.py upload logic.
Keeps the existing parser contract but uploads findings in batches.
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error

# NOTE:
# Replace the parse_ocsf() implementation below with the one from your
# existing script if you want identical parsing behaviour.
from datetime import datetime, timezone
import uuid

SEVERITY_MAP={"critical":4,"high":3,"medium":2,"low":1,"informational":0}
ATTACK_RELATIONSHIPS={}

def parse_ocsf(filepath:str, provider:str):
    try:
        with open(filepath,"r") as f:
            raw=json.load(f)
    except FileNotFoundError:
        print(f"[warn] File not found: {filepath}, skipping.")
        return None, [], [], []
    findings=raw if isinstance(raw,list) else raw.get("findings",[])
    parsed=[]
    resources={}
    scan_id=str(uuid.uuid4())
    counts={"total":0,"passed":0,"failed":0,"critical":0,"high":0,"medium":0,"low":0}
    for f in findings:
        sev=(f.get("severity","low") or "low").lower()
        status="PASS" if f.get("status_code","FAIL") in ("PASS","pass") else "FAIL"
        res=f.get("resources",[{}])[0] if f.get("resources") else {}
        uid=res.get("uid","") or res.get("id","")
        svc=(f.get("cloud",{}).get("service",{}).get("name","") or f.get("service","")).lower()
        parsed.append({
            "id":str(uuid.uuid4()),
            "scan_run_id":scan_id,
            "provider":provider,
            "service":svc,
            "check_id":f.get("check_id",f.get("type_uid","")),
            "check_title":f.get("check_title",f.get("message","")),
            "status":status,
            "severity":sev,
            "resource_uid":uid,
            "resource_name":res.get("name",uid),
            "resource_type":res.get("type",""),
            "region":f.get("cloud",{}).get("region","global"),
            "description":f.get("description",""),
            "remediation":""
        })
        counts["total"]+=1
        if status=="PASS":
            counts["passed"]+=1
        else:
            counts["failed"]+=1
            if sev in counts:
                counts[sev]+=1
        if uid and svc:
            rid=f"{provider}:{svc}:{uid}"
            resources.setdefault(rid,{
                "id":rid,"provider":provider,"service":svc,
                "resource_uid":uid,
                "resource_name":res.get("name",uid),
                "resource_type":res.get("type",""),
                "region":f.get("cloud",{}).get("region","global"),
                "risk_score":SEVERITY_MAP.get(sev,0)
            })
    scan={
        "id":scan_id,
        "provider":provider,
        "scanned_at":datetime.now(timezone.utc).isoformat(),
        "score":round((counts["passed"]/counts["total"])*100,1) if counts["total"] else 0,
        **counts
    }
    return scan,parsed,list(resources.values()),[]

def post(url,token,body,retries=3):
    data=json.dumps(body).encode()
    req=urllib.request.Request(
        url,data=data,method="POST",
        headers={
            "Content-Type":"application/json",
            "Authorization":f"Bearer {token}",
            "User-Agent":"ProwlerUploader/2.0",
            "Accept":"application/json"
        })
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req,timeout=120) as r:
                print(f"[ok] HTTP {r.status} ({len(data):,} bytes)")
                return
        except urllib.error.HTTPError as e:
            body=e.read().decode(errors="ignore")
            print(f"[warn] HTTP {e.code}: {body}")
            if attempt==retries-1:
                raise
            time.sleep(2**attempt)

def push(url,token,scan,findings,resources,edges):
    chunk=100
    total=(len(findings)+chunk-1)//chunk
    print(f"Uploading {len(findings)} findings in {total} batches")
    for idx in range(total):
        batch=findings[idx*chunk:(idx+1)*chunk]
        payload={
            "scan_run":scan if idx==0 else {"id":scan["id"]},
            "findings":batch,
            "resources":resources if idx==total-1 else [],
            "edges":edges if idx==total-1 else []
        }
        print(f"Batch {idx+1}/{total}: findings={len(batch)} resources={len(payload['resources'])} edges={len(payload['edges'])}")
        post(url,token,payload)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--file",required=True)
    ap.add_argument("--provider",required=True)
    ap.add_argument("--url",required=True)
    ap.add_argument("--token",required=True)
    a=ap.parse_args()
    scan,findings,resources,edges=parse_ocsf(a.file,a.provider)
    if scan is None:
        print("[skip] No findings file, exiting cleanly.")
        sys.exit(0)
    push(a.url,a.token,scan,findings,resources,edges)

if __name__=="__main__":
    main()