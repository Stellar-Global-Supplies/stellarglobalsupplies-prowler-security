# SecureView — Cloud Security Dashboard

A Wiz-like security dashboard built on your existing Cloudflare stack.  
**Free. No CC. No server. Hourly scans.**

## Architecture

```
GitHub Actions (hourly, public repo — unlimited free minutes)
    ↓  Prowler scans AWS + Cloudflare
    ↓  parse_and_push.py parses JSON → pushes findings
    ↓
CF Worker API (prowler-api.yourname.workers.dev)
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
# Set your ingest auth token (make it a long random string)
wrangler secret put INGEST_TOKEN

# Deploy
wrangler deploy
# Note the URL: https://prowler-api.yourname.workers.dev
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
| `VITE_API_URL` | `https://prowler-api.yourname.workers.dev` |

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
| `AWS_ACCESS_KEY_ID` | IAM user access key (read-only policy) |
| `AWS_SECRET_ACCESS_KEY` | IAM user secret key |
| `CLOUDFLARE_API_TOKEN` | CF API token (read permissions only) |
| `CLOUDFLARE_ACCOUNT_ID` | Your CF account ID |
| `CF_WORKER_INGEST_URL` | `https://prowler-api.yourname.workers.dev/ingest` |
| `CF_WORKER_INGEST_TOKEN` | Same token you set with `wrangler secret put` |

### 7. Create AWS read-only IAM policy

Create an IAM user with this policy for Prowler:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetBucketAcl", "s3:GetBucketPolicy", "s3:GetBucketPublicAccessBlock",
      "s3:GetEncryptionConfiguration", "s3:GetBucketVersioning", "s3:ListAllMyBuckets",
      "route53:ListHostedZones", "route53:GetHostedZone", "route53:ListResourceRecordSets",
      "iam:GetAccountPasswordPolicy", "iam:GetAccountSummary",
      "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"
    ],
    "Resource": "*"
  }]
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
│   ├── wrangler.toml          # CF Worker config
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
