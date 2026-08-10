# Resource Identification & Scan Visibility Fix

## Issues Fixed

### 1. Resource Identification
**Problem**: Could not identify which specific resource (S3 bucket, Lambda function, etc.) was affected by a finding.

**Solution**: Enhanced the findings display to prominently show resource information:
- Resource name displayed in accent color in the main table
- Resource UID/ARN shown below the name when different
- Expanded view now shows a dedicated "Affected Resource" section with:
  - Resource Name
  - Resource ID / ARN
  - Resource Type
  - Region

### 2. Service Scan Visibility
**Problem**: Only ACM findings were visible, even though S3, Lambda, CloudFront, and Route53 were configured in the scan.

**Solution**: Added comprehensive logging to track which services are being scanned:
- Service breakdown logged after parsing findings
- Shows count of findings per service
- Helps identify if services are being scanned but have no failing checks

## Changes Made

### Dashboard Updates

#### `dashboard/src/pages/Findings.jsx`
- **Enhanced Resource Column**: Now shows both resource name (in accent color) and resource UID
- **Improved Expanded View**: Added dedicated "Affected Resource" section with full details
- **Wider Resource Column**: Increased from 140px to 160px for better visibility

#### `dashboard/src/pages/Dashboard.jsx`
- **Added Resource Count Column**: Services table now shows number of resources checked per service
- **Better Visibility**: Helps identify which services have resources in scope

### Backend Updates

#### `scripts/parse_and_push.py`
- **Added Service Breakdown Logging**: After parsing findings, logs the count per service
- **Example Output**:
  ```
  [info] Service breakdown:
         acm: 15 findings
         s3: 8 findings
         lambda: 3 findings
         cloudfront: 2 findings
  ```

## How to Use

### Viewing Resource Information

1. **Navigate to Findings Page**: Go to `/findings` in the dashboard
2. **Resource Column**: Each finding shows:
   - **Resource Name** (accent color, bold) - e.g., "my-bucket-name"
   - **Resource UID** (monospace, muted) - e.g., "arn:aws:s3:::my-bucket-name"
3. **Expand a Finding**: Click any finding to see full details:
   - Resource Name
   - Resource ID / ARN
   - Resource Type
   - Region

### Filtering by Resource

Use the search box to filter findings by:
- Resource name
- Resource UID/ARN
- Check title
- Description

Example searches:
- `arn:aws:s3:::my-bucket`
- `my-lambda-function`
- `us-east-1`

### Understanding Service Coverage

#### Check the Workflow Logs
After each scan, the GitHub Actions workflow logs will show:
```
[info] Service breakdown:
       acm: 15 findings
       s3: 8 findings
       lambda: 3 findings
```

#### Check the Dashboard
The Services table on the Dashboard shows:
- **Resources** column: Number of resources checked per service
- **Checks** column: Number of security checks executed
- **Coverage** column: Percentage of passing checks

If a service shows 0 resources, it means:
- No resources of that type exist in your account, OR
- The service scan hasn't run yet

## Scan Configuration

The workflow is configured to scan all required services:

```yaml
# .github/workflows/prowler-scan.yml
--service iam --service s3 --service lambda --service rds \
--service cloudwatch --service cloudwatchlogs --service stepfunctions \
--service cloudfront --service route53 --service acm
```

**Scan Schedule:** Twice daily at 12 AM and 12 PM UTC
```yaml
on:
  schedule:
    - cron: '0 0,12 * * *'   # Twice daily
```

### Why Only ACM Might Show Findings

If you're only seeing ACM findings, possible reasons:

1. **Other services have no failing checks** - All S3, Lambda, etc. checks are passing
2. **No resources exist** - Your account might not have S3 buckets, Lambda functions, etc.
3. **Resources are compliant** - All resources pass their security checks

To verify:
- Check the workflow logs for "Service breakdown" section
- Look at the Dashboard's Services table for resource counts
- Use the provider filter to see all findings (including PASS)

## Viewing All Checks (Including Passes)

By default, the findings page shows FAIL status only. To see all checks:

1. Click the **"All"** button in the Status toggle
2. Or navigate to: `/findings?status=`

This will show:
- All PASS findings (resources that are compliant)
- All FAIL findings (resources with issues)
- Makes it easy to see which services were scanned

## Troubleshooting

### No resource information showing
- Ensure the Prowler json-results patch is applied
- Check that findings have `resource_uid` and `resource_name` fields
- Verify the database schema includes resource columns

### Service not appearing in dashboard
- Check workflow logs for errors during that service's scan
- Verify the service is listed in the workflow configuration
- Ensure Prowler has credentials to scan that service

### Only seeing ACM findings
This is normal if:
- Other services have no failing checks (all passing)
- You have the status filter set to "FAIL" only
- Other services don't have resources in your account

**To see all findings**: Change status filter to "All" or remove the status parameter

## Next Steps

1. **Trigger a new scan**: Manually trigger the GitHub Actions workflow
2. **Check the logs**: Look for the "Service breakdown" section
3. **View findings**: Navigate to the dashboard to see enhanced resource information
4. **Filter and search**: Use the search box to find specific resources

## Technical Details

### Database Schema
The `findings` table includes:
- `resource_uid` - Unique identifier (ARN, ID, etc.)
- `resource_name` - Human-readable name
- `resource_type` - Type of resource (e.g., "AWS::S3::Bucket")
- `region` - AWS region

### Data Flow
1. Prowler scans AWS services
2. json-results exporter captures all findings with resource details
3. parse_and_push.py logs service breakdown
4. Worker ingests findings into D1 database
5. Dashboard displays findings with enhanced resource information