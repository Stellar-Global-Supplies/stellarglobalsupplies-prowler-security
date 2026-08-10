# Database Scanners Setup Guide

This guide explains how to set up and use the NeonDB and Supabase security scanners.

## Prerequisites

- GitHub repository with Actions enabled
- NeonDB account with API access
- Supabase account with project
- Cloudflare Worker deployment (for dashboard)

## Step 1: Add GitHub Secrets

Go to your GitHub repository → Settings → Secrets and variables → Actions → New repository secret

### For NeonDB:

1. **NEON_API_KEY**
   - Go to NeonDB Console → Settings → API Keys
   - Create a new API key with appropriate permissions
   - Copy the key and add it as `NEON_API_KEY`

2. **NEON_PROJECT_ID** (Optional)
   - If you want to scan a specific project only
   - Get it from NeonDB Console URL: `https://console.neon.tech/app/projects/{PROJECT_ID}`
   - Add it as `NEON_PROJECT_ID`
   - Leave blank to scan all projects

### For Supabase:

1. **SUPABASE_URL**
   - Go to Supabase Dashboard → Project Settings → API
   - Copy the "Project URL" (e.g., `https://xxx.supabase.co`)
   - Add it as `SUPABASE_URL`

2. **SUPABASE_API_KEY**
   - In the same API settings page
   - Copy the "service_role" key (⚠️ Keep this secret!)
   - Add it as `SUPABASE_API_KEY`
   - ⚠️ Never expose this key in client-side code

## Step 2: Verify Secrets Are Set

```bash
# List all secrets (you'll see names but not values)
gh secret list

# Or check in GitHub UI: Settings → Secrets and variables → Actions
```

## Step 3: Trigger a Scan

### Option A: Manual Trigger (Recommended for First Run)

1. Go to GitHub repository → Actions tab
2. Select "Prowler Security Scan" workflow
3. Click "Run workflow" → "Run workflow"
4. Monitor the workflow run

You should see parallel jobs running:
- ✅ scan-aws (matrix of 10 services)
- ✅ scan-neon
- ✅ scan-supabase
- ✅ scan-cloudflare

### Option B: Wait for Scheduled Scan

The workflow runs automatically every hour (cron: `0 * * * *`)

## Step 4: Monitor Scan Results

### Check Workflow Logs

1. Click on the running workflow
2. Click on the job name (e.g., "Scan NeonDB")
3. Click on the step "Run NeonDB Security Scan"
4. You should see output like:

```
[info] Starting NeonDB security scan...
[info] Found 2 NeonDB project(s)
[info] Scanning NeonDB project: project-id-123
[info] Scan complete: 6 checks, 83.3% score
[info] Results: 5 passed, 1 failed
[ok] Results written to ./output/neon-findings.results.json

[info] Service breakdown:
       database: 6 findings
```

### Check Dashboard

1. Navigate to your dashboard
2. Go to Findings page
3. Use filters to see database findings:
   - Provider: `neon` or `supabase`
   - Service: `database`
4. Expand findings to see detailed resource information

## Step 5: Understanding Results

### NeonDB Findings

Each NeonDB project gets 6 security checks:

| Check ID | Severity | Description |
|----------|----------|-------------|
| `neon_encryption_at_rest` | Critical | Verifies AES-256 encryption |
| `neon_ssl_tls_enabled` | High | Verifies SSL/TLS enforcement |
| `neon_ip_allowlist` | High | Checks IP allowlist configuration |
| `neon_audit_logging` | Medium | Verifies audit logging |
| `neon_automated_backups` | High | Checks automated backups |
| `neon_connection_security` | Medium | Verifies connection pooling |

### Supabase Findings

Each Supabase project gets 8 security checks:

| Check ID | Severity | Description |
|----------|----------|-------------|
| `supabase_ssl_tls_enforced` | Critical | Verifies HTTPS enforcement |
| `supabase_api_key_security` | Critical | API key security guidance |
| `supabase_rls_enabled` | High | Row Level Security status |
| `supabase_email_confirmation` | High | Email confirmation requirement |
| `supabase_mfa_enabled` | High | MFA configuration |
| `supabase_audit_logging` | Medium | Audit logging availability |
| `supabase_realtime_auth` | High | Realtime authentication |
| `supabase_storage_security` | Medium | Storage bucket permissions |

## Step 6: Filtering and Viewing

### In the Dashboard

**Findings Page:**
- Filter by provider: `neon` or `supabase`
- Filter by severity: Critical, High, Medium, Low
- Search by resource name or ID
- Click on findings to expand and see full details

**Dashboard Home:**
- Services table shows database provider
- Provider breakdown shows neon/supabase scores
- Severity cards show database-related findings

### Example Filters

```
# See all NeonDB findings
/findings?provider=neon

# See all Supabase high/critical findings
/findings?provider=supabase&severity=high

# Search for specific project
/findings?q=my-project-name
```

## Troubleshooting

### NeonDB Scanner Not Running

**Check:**
1. `NEON_API_KEY` secret is set correctly
2. API key has required permissions
3. Workflow logs show the error

**Common Issues:**
- Invalid API key → Regenerate in NeonDB console
- Network timeout → Check NeonDB API status
- No projects found → Verify project ID or create a project

### Supabase Scanner Not Running

**Check:**
1. `SUPABASE_URL` is correct format (`https://xxx.supabase.co`)
2. `SUPABASE_API_KEY` is the service_role key (not anon key)
3. Project is accessible

**Common Issues:**
- 401 Unauthorized → Check API key permissions
- Connection timeout → Verify URL is correct
- RLS check failing → Enable RLS in Supabase console

### No Findings Appearing

**Check:**
1. Scanner ran successfully (check workflow logs)
2. Results file was created (`./output/neon-findings.results.json`)
3. parse_and_push.py uploaded successfully
4. Worker ingest endpoint is accessible

**Debug:**
```bash
# Check if results file exists
ls -la ./output/

# Check file contents
cat ./output/neon-findings.results.json | jq .

# Test upload manually
python3 scripts/parse_and_push.py \
  --file ./output/neon-findings.results.json \
  --provider neon \
  --url $INGEST_URL \
  --token $INGEST_TOKEN
```

## Security Considerations

### API Key Storage

✅ **DO:**
- Store keys in GitHub Secrets
- Use service_role key only in backend/workflows
- Rotate keys regularly
- Use minimal required permissions

❌ **DON'T:**
- Commit keys to git
- Expose keys in logs
- Use service_role key in client-side code
- Share keys publicly

### Scanner Permissions

The scanners only perform **read-only** operations:
- ✅ Read project configuration
- ✅ Read security settings
- ✅ Read table metadata
- ❌ No data modification
- ❌ No schema changes
- ❌ No user management

## Customization

### Adding More Checks

Edit the scanner scripts to add custom checks:

```python
def check_custom_security(url: str, api_key: str) -> Dict[str, Any]:
    """Your custom security check."""
    # Your logic here
    return {
        "check_id": "custom_check_id",
        "check_title": "Your Check Title",
        "status": "PASS",  # or "FAIL"
        "severity": "high",  # critical, high, medium, low
        "resource_uid": url,
        "resource_name": "Resource Name",
        "resource_type": "Resource Type",
        "region": "us-east-1",
        "description": "Check description",
        "remediation": "How to fix if failed",
    }
```

Then add it to the `scan_project` function's checks list.

### Changing Scan Frequency

Edit `.github/workflows/prowler-scan.yml`:

```yaml
on:
  schedule:
    - cron: '0 * * * *'   # Every hour
    # - cron: '0 */6 * * *'   # Every 6 hours
    # - cron: '0 0 * * *'     # Daily at midnight
```

## Next Steps

1. ✅ Add GitHub secrets
2. ✅ Trigger first scan
3. ✅ Verify results in dashboard
4. ✅ Review any FAIL findings
5. ✅ Fix security issues
6. ✅ Re-scan to verify fixes

## Support

If you encounter issues:
1. Check workflow logs for errors
2. Verify secrets are set correctly
3. Test API access manually
4. Review scanner output files
5. Check dashboard for uploaded findings