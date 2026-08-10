# Stellar Security View — Powered by Prowler

A Wiz-like security dashboard built on Prowler and your existing Cloudflare stack.  
**Free. No CC. No server. Hourly scans.**

## Architecture

```
GitHub Actions (hourly, public repo — unlimited free minutes)
    ↓  Prowler scans AWS + Cloudflare
    ↓  parse_and_push.py parses JSON → pushes findings
    ↓
CF Worker API (prowler-api.workwithprasadbhavsar.workers.dev)
    ↓  writes to
CF D1 Database (prowler-db)
    ↑  reads from
CF Pages Dashboard (security.yourdomain.com)
    ↑  auth via
Supabase Auth
```

---

## Setup — Step by step

### 1. Create D1 database

```bash
cd worker
npm install -g wrangler
wrangler login
wrangler d1 create prowler-db
# Copy the database_id into wrangler.toml
wrangler d1 execute prowler-db --file=../db/schema.sql
```

### 2. Deploy the Worker

```bash
# Create the ingest token secret in the Secrets Store
npx wrangler secrets-store secret create <STORE_ID> --name CF_API_TOKEN --scopes workers --remote

# Deploy
wrangler deploy
# Note the URL: https://prowler-api.workwithprasadbhavsar.workers.dev
```

### 3. Deploy the Dashboard to CF Pages

```bash
cd dashboard
npm install
```

In Cloudflare Pages → New Project → Connect GitHub repo:

- **Build command:** `npm run build`
- **Output directory:** `dist`
- **Environment variables (Settings → Environment Variables):**

| Key | Value |
|-----|-------|
| `VITE_SUPABASE_URL` | Your Supabase project URL |
| `VITE_SUPABASE_ANON_KEY` | Your Supabase anon key |
| `VITE_API_URL` | `https://prowler-api.workwithprasadbhavsar.workers.dev` |

### 4. Custom domain

In CF Pages → Custom Domains → Add `security.yourdomain.com`  
CF handles the SSL cert automatically.

### 5. Set up Supabase Auth

In your Supabase dashboard:
1. Authentication → Providers → enable Email
2. Authentication → URL Configuration → add your CF Pages URL to **Site URL**
3. Optionally enable GitHub OAuth provider

### 6. Set up GitHub Actions

Add these secrets to your GitHub repo (Settings → Secrets → Actions):

| Secret | Value |
|--------|-------|
| `AWS_ROLE_ARN` | IAM role ARN with OIDC trust (replaces access keys) |
| `CLOUDFLARE_API_TOKEN` | CF API token (read permissions only) |
| `CLOUDFLARE_ACCOUNT_ID` | Your CF account ID |
| `CF_WORKER_INGEST_URL` | `https://prowler-api.workwithprasadbhavsar.workers.dev/ingest` |
| `CF_WORKER_INGEST_TOKEN` | Same token as the `CF_API_TOKEN` secret in your Secrets Store |

### 7. Set up AWS OIDC IAM role

The workflow uses **OIDC** to authenticate with AWS (no long-lived access keys needed).

1. Create an OIDC Identity Provider in IAM:
   - Provider URL: `https://token.actions.githubusercontent.com`
   - Audience: `sts.amazonaws.com`
2. Create a role with this trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:Stellar-Global-Supplies/stellarglobalsupplies-prowler-security:*"
        }
      }
    }
  ]
}
```

3. Attach a read-only policy to the role. **Use AWS-managed `ReadOnlyAccess`**
   (or `SecurityAudit`) — a hand-curated list of a dozen permissions is *not*
   enough.  Prowler runs ~630 checks across dozens of services (EC2, IAM,
   Lambda, RDS, S3, Config, GuardDuty, …).  If the role only has a few
   `Describe`/`List` permissions, every check still *executes* but returns
   **0 resources**, producing an empty scan:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": "ReadOnlyAccess",
       "Resource": "*"
     }]
   }
   ```

   Replace the `Action` above with the ARN of the managed policy if you
   attach it via the AWS console instead:

   `arn:aws:iam::aws:policy/ReadOnlyAccess`

   The **minimum viable policy** if you cannot use `ReadOnlyAccess`
   (covers the services Prowler scans most commonly):

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "acm:Describe*", "acm:List*", "access-analyzer:List*", "access-analyzer:Get*",
           "apigateway:GET", "autoscaling:Describe*", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:ListTrails",
           "cloudwatch:Describe*", "cloudwatch:Get*", "cloudwatch:List*",
           "config:Describe*", "config:List*", "config:Get*",
           "ec2:Describe*", "ecr:Describe*", "ecr:List*", "ecs:Describe*", "ecs:List*",
           "eks:Describe*", "eks:List*", "elasticloadbalancing:Describe*",
           "guardduty:List*", "guardduty:Get*", "iam:Get*", "iam:List*",
           "kms:Describe*", "kms:Get*", "kms:List*",
           "lambda:Get*", "lambda:List*", "logs:Describe*", "logs:Get*", "logs:List*",
           "rds:Describe*", "rds:List*", "route53:List*", "route53:Get*",
           "s3:Get*", "s3:List*", "sns:Get*", "sns:List*",
           "sqs:Get*", "sqs:List*", "sts:GetCallerIdentity",
           "waf:List*", "waf:Get*", "wafv2:List*", "wafv2:Get*"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

### 8. Create Cloudflare API token

In CF Dashboard → My Profile → API Tokens → Create Token:
- Use **Read all resources** template
- Scope to your account

---

## Project structure

```
prowler-dashboard/
├── .github/workflows/
│   └── prowler-scan.yml       # Hourly GitHub Actions scan
├── scripts/
│   └── parse_and_push.py      # Parses Prowler JSON → pushes to Worker
├── worker/
│   ├── wrangler.toml          # CF Worker config (Secrets Store, D1, observability)
│   ├── package.json           # Worker dependencies (wrangler, workers-types)
│   ├── tsconfig.json          # TypeScript config
│   └── src/index.ts           # Worker API (ingest + GET endpoints)
├── dashboard/
│   ├── index.html
│   ├── vite.config.js
│   ├── package.json
│   └── src/
│       ├── main.jsx
│       ├── App.jsx             # Auth routing
│       ├── index.css           # Design tokens
│       ├── lib/
│       │   ├── supabase.js     # Supabase client
│       │   └── api.js          # CF Worker API client
│       ├── pages/
│       │   ├── Login.jsx       # Supabase auth (email + GitHub OAuth)
│       │   ├── Dashboard.jsx   # Overview with score gauge + trend chart
│       │   ├── Findings.jsx    # Filterable findings table
│       │   └── AttackGraph.jsx # D3 force-directed attack path graph
│       └── components/
│           └── Layout.jsx      # Sidebar + navigation
└── db/
    └── schema.sql              # D1 tables + indexes
```

---

## Dashboard features

- **Security score gauge** — overall posture % with animated ring
- **Severity cards** — critical / high / medium / low counts, click to filter findings
- **Trend chart** — D3 line chart of score over last 7 days (hourly granularity)
- **Provider breakdown** — score and top issues per provider (AWS, Cloudflare)
- **Findings table** — filterable by severity, status, provider, free-text search; expandable rows with description + remediation
- **Attack graph** — D3 force-directed graph with:
  - Nodes colored by severity, sized by finding count
  - Animated glow on critical nodes
  - Edge arrows showing attack path direction
  - Hover tooltips with resource details
  - Click panel for deep node detail
  - Filter by severity
  - Drag nodes, scroll to zoom, pan

---

## Cost

| Service | Cost |
|---------|------|
| GitHub Actions (public repo) | **Free — unlimited** |
| CF Workers | Free (100k req/day) |
| CF D1 | Free (5M reads/day, 100k writes/day) |
| CF Pages | Free |
| Supabase Auth | Free (50k MAU) |
| Custom domain (if you have it) | Already have it |
| **Total** | **$0** |

# Prowler `json-results` Output Format Patch

This patch adds a new `--output-formats json-results` mode to Prowler that
exports **every executed check** — not just failures — as a flat JSON array
suitable for ingestion into a Cloudflare Worker / D1 pipeline.

---

## Problem

Stock Prowler only exports *findings* (FAIL results by default). When all
checks pass it prints `"There are no findings"` and writes no output file.
This makes it impossible to build compliance dashboards, posture scores, or
historical trend reports because passing checks are invisible.

---

## Solution

A new output format `json-results` that:

- Exports **every** executed check result (PASS, FAIL, MANUAL, MUTED, …)
- **Never** filters results
- **Always** writes a file, even when zero findings exist
- Leaves every existing format (`csv`, `json-ocsf`, `html`, `json-asff`,
  `sarif`) completely unchanged

---

## Files

```
prowler_patches/
├── apply_patch.py                          # Idempotent installer
├── README.md                               # This file
├── prowler/
│   └── lib/
│       └── outputs/
│           └── json_results/
│               ├── __init__.py
│               └── json_results.py         # The exporter
└── tests/
    └── lib/
        └── outputs/
            └── json_results/
                └── test_json_results.py    # 35 unit tests
```

---

## Installation

```bash
# 1. Install Prowler (if not already installed)
pip install prowler

# 2. Apply the patch (idempotent — safe to run again after pip upgrades)
python prowler_patches/apply_patch.py

# 3. Verify
python -c "from prowler.config.config import available_output_formats; print(available_output_formats)"
# → ['csv', 'json-asff', 'json-ocsf', 'html', 'sarif', 'json-results']
```

The script:
1. Copies `prowler/lib/outputs/json_results/` into the installed package
2. Adds `"json-results"` to `available_output_formats` in `config/config.py`
3. Registers the dispatch block in `__main__.py`
4. Adds a summary-table line in `lib/outputs/summary_table.py`

> **Re-run after every `pip install --upgrade prowler`** to re-apply the patch.

---

## Usage

### AWS

```bash
prowler aws \
  --output-formats json-results \
  --output-directory ./output
```

Output: `output/prowler-output-aws-<TIMESTAMP>.results.json`

### Cloudflare

```bash
prowler cloudflare \
  --output-formats json-results \
  --output-directory ./output
```

Output: `output/prowler-output-cloudflare-<TIMESTAMP>.results.json`

### Combined with other formats (existing formats are unchanged)

```bash
prowler aws \
  --output-formats csv json-ocsf json-results \
  --output-directory ./output
```

### Custom filename

```bash
prowler aws \
  --output-formats json-results \
  --output-directory ./output \
  --output-filename aws-results
# → output/aws-results.results.json
```

---

## Output Schema

```json
{
  "schema_version": "1.0.0",
  "total": 247,
  "results": [
    {
      "finding_uid": "prowler-aws-s3_bucket_public_access-123456789012-us-east-1-my-bucket",
      "provider": "aws",
      "auth_method": "profile: default",
      "account_uid": "123456789012",
      "account_name": "production",
      "account_email": "aws@example.com",
      "account_organization_uid": "o-abc123def456",
      "account_organization_name": "MyOrg",
      "account_ou_uid": "ou-root-abc",
      "account_ou_name": "RootOU",
      "account_tags": { "env": "prod" },
      "partition": "aws",
      "region": "us-east-1",
      "resource_uid": "arn:aws:s3:::my-bucket",
      "resource_name": "my-bucket",
      "resource_type": "AwsS3Bucket",
      "resource_details": "{}",
      "resource_tags": { "team": "security" },
      "resource_metadata": {},
      "check_id": "s3_bucket_public_access",
      "check_title": "Ensure S3 Bucket Does Not Allow Public Access",
      "check_type": ["Software and Configuration Checks"],
      "check_description": "Checks whether public access is blocked on S3 buckets.",
      "service_name": "s3",
      "subservice_name": "",
      "status": "PASS",
      "status_extended": "Bucket my-bucket has public access blocked.",
      "muted": false,
      "severity": "high",
      "risk": "Data exposure via public S3 bucket.",
      "compliance": {
        "CIS AWS 1.4": ["2.1.1"]
      },
      "compliance_frameworks": ["CIS AWS 1.4|2.1.1"],
      "categories": ["security"],
      "depends_on": [],
      "related_to": [],
      "remediation": {
        "recommendation_text": "Enable S3 block public access settings.",
        "recommendation_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        "code_cli": "aws s3api put-public-access-block --bucket my-bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
        "code_terraform": "resource \"aws_s3_bucket_public_access_block\" \"example\" { ... }",
        "code_native_iac": "",
        "code_other": ""
      },
      "documentation_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
      "notes": "",
      "additional_urls": [],
      "timestamp": "2025-01-15T10:30:00",
      "prowler_version": "5.37.1",
      "raw_metadata": {
        "provider": "aws",
        "checkid": "s3_bucket_public_access"
      }
    }
  ]
}
```

### Status Values

| Value    | Meaning                                        |
|----------|------------------------------------------------|
| `PASS`   | Check passed                                   |
| `FAIL`   | Check failed (finding)                         |
| `MANUAL` | Check requires manual verification             |
| `MUTED`  | Result suppressed by a mute rule               |

The underlying pass/fail result for muted findings is preserved in
`status_extended`.

---

## D1 / Cloudflare Worker Ingestion

The JSON file is designed for direct ingestion.  Minimal Worker pseudocode:

```typescript
async function ingest(results: ResultsFile, db: D1Database) {
  const stmt = db.prepare(`
    INSERT OR REPLACE INTO scan_results (
      finding_uid, provider, account_uid, region,
      check_id, check_title, status, severity,
      compliance_frameworks, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const r of results.results) {
    await stmt.bind(
      r.finding_uid, r.provider, r.account_uid, r.region,
      r.check_id, r.check_title, r.status, r.severity,
      JSON.stringify(r.compliance_frameworks), r.timestamp
    ).run();
  }
}
```

---

## Running Tests

```bash
cd /path/to/stellarglobalsupplies-prowler-security
python -m pytest prowler_patches/tests/ -v
```

All 35 tests should pass.

---

## Architecture Notes

### What the patch touches

| File | Change |
|------|--------|
| `prowler/lib/outputs/json_results/json_results.py` | **New file** – the exporter |
| `prowler/config/config.py` | Adds `"json-results"` to `available_output_formats` |
| `prowler/__main__.py` | Imports `JSONResults`; adds dispatch block in the output-format loop |
| `prowler/lib/outputs/summary_table.py` | Adds file path line in the post-scan summary |

### Zero-resource scans still produce a valid file

The exporter's `__init__` is overridden so the output file descriptor is
always created, and the `json-results` dispatch block in `__main__.py` is
injected **outside** Prowler's `if finding_outputs:` guard.  This means a
no-resource scan (e.g. an AWS role with no permission to enumerate anything)
still writes:

```json
{
  "schema_version": "1.0.0",
  "total": 0,
  "results": []
}
```

…instead of a 0-byte file.  The downstream `parse_and_push.py` then logs
`Loaded 0 records` and pushes a zero-finding `scan_run` row so the dashboard
shows "no resources found" rather than hiding the provider entirely.

### Custom Cloudflare services source path

The custom Cloudflare service packages (`workers`, `pages`, `d1`, `kv`) are
tracked in the repo root at `prowler/providers/cloudflare/services/`.  The
patch script resolves this path relative to `prowler_patches/`, so it always
finds them — no `prowler_patches/prowler/providers/` copy is required.

### What the patch does NOT touch

- `json-ocsf` / `html` / `csv` / `json-asff` / `sarif` — zero changes
- Compliance report outputs
- Finding filtering logic
- The `Finding.generate_output` pipeline
- GitHub Actions workflow
- Cloudflare Worker

### Why no filtering?

`finding_outputs` in `__main__.py` is built from the raw `findings` list
returned by `execute_checks`.  That list contains every `Check_Report`
produced by every executed check regardless of status.  The exporter simply
serialises all of them.  The existing exporters filter implicitly through
their `transform` methods; `JSONResults.transform` does not.