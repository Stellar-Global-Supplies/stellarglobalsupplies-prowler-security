-- Clean up Cloudflare data from Prowler Dashboard
-- Run this to remove all Cloudflare data before re-scanning

-- Option 1: Delete only Cloudflare data (keeps AWS data)
-- Use this if you want to preserve AWS scan history

DELETE FROM graph_edges
WHERE source_id IN (
    SELECT id FROM resources WHERE provider = 'cloudflare'
) OR target_id IN (
    SELECT id FROM resources WHERE provider = 'cloudflare'
);

DELETE FROM findings
WHERE provider = 'cloudflare';

DELETE FROM resources
WHERE provider = 'cloudflare';

DELETE FROM scan_runs
WHERE provider = 'cloudflare';

-- Option 2: Nuclear option - Delete ALL data and recreate tables
-- Uncomment below if you want to start completely fresh
-- WARNING: This will delete ALL data including AWS scans

DROP TABLE IF EXISTS graph_edges;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS resources;
DROP TABLE IF EXISTS scan_runs;

-- Verification queries (run these to check what's left)

-- Check remaining providers
-- SELECT provider, COUNT(*) as count FROM scan_runs GROUP BY provider;

-- Check remaining services
-- SELECT service, provider, COUNT(*) as count FROM findings GROUP BY service, provider ORDER BY count DESC;

-- Check for any remaining Cloudflare data
-- SELECT * FROM scan_runs WHERE provider = 'cloudflare';
-- SELECT * FROM findings WHERE provider = 'cloudflare';
-- SELECT * FROM resources WHERE provider = 'cloudflare';