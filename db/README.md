# Database Management

## Clean Up Cloudflare Data

If you suspect data duplication or want to clean up Cloudflare scan data, use the provided SQL script.

### Option 1: Delete Only Cloudflare Data (Recommended)

This removes all Cloudflare data while preserving your AWS scan history.

```bash
wrangler d1 execute prowler-db --file=db/cleanup_cloudflare.sql
```

**What it deletes:**
- All Cloudflare findings
- All Cloudflare resources
- All Cloudflare scan runs
- Related graph edges

**What it keeps:**
- All AWS scan data
- All AWS findings and resources

### Option 2: Complete Reset (Nuclear Option)

If you want to start completely fresh with ALL data:

1. Edit `db/cleanup_cloudflare.sql`
2. Uncomment the "Option 2" section (lines 20-24)
3. Comment out "Option 1" section (lines 8-17)
4. Run the script:

```bash
wrangler d1 execute prowler-db --file=db/cleanup_cloudflare.sql
```

5. Recreate tables by running:

```bash
wrangler d1 execute prowler-db --file=db/schema.sql
```

**WARNING:** This deletes ALL data including AWS scans!

### Verification

After cleanup, verify the data is removed:

```bash
# Check remaining providers
wrangler d1 execute prowler-db --command="SELECT provider, COUNT(*) as count FROM scan_runs GROUP BY provider;"

# Check remaining services
wrangler d1 execute prowler-db --command="SELECT service, provider, COUNT(*) as count FROM findings GROUP BY service, provider ORDER BY count DESC;"

# Verify no Cloudflare data remains
wrangler d1 execute prowler-db --command="SELECT COUNT(*) as cloudflare_findings FROM findings WHERE provider = 'cloudflare';"
```

### Preventing Duplication

To avoid data duplication in future scans:

1. **Clean before re-scanning**: Run the cleanup script before triggering a new scan
2. **Use unique scan IDs**: The system generates unique scan IDs automatically
3. **Check workflow logs**: Look for the service breakdown to verify data
4. **Monitor database**: Periodically check for duplicate entries

### Common Issues

**Issue**: Duplicate findings appearing
**Solution**: Run the cleanup script and trigger a fresh scan

**Issue**: Old scan data cluttering the dashboard
**Solution**: Use Option 1 to clean only specific providers, or Option 2 for a complete reset

**Issue**: Graph edges showing old relationships
**Solution**: The cleanup script automatically removes related graph edges

## Schema Management

### View Current Schema

```bash
wrangler d1 execute prowler-db --command="SELECT sql FROM sqlite_master WHERE type='table';"
```

### Recreate Tables (if needed)

```bash
wrangler d1 execute prowler-db --file=db/schema.sql
```

This is safe to run multiple times - it uses `CREATE TABLE IF NOT EXISTS`.