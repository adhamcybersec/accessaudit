# AWS IAM Connector

The AWS connector uses boto3 to scan IAM users, roles, policies, and permissions.

## Authentication

### Environment Variables

```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"
```

### AWS CLI Profile

```bash
export AWS_PROFILE="my-profile"
```

### IAM Role (Recommended)

For EC2, ECS, Lambda, or any AWS service, use IAM roles instead of access keys.
AccessAudit automatically uses the instance's IAM role credentials.

## Configuration

```yaml
providers:
  aws:
    enabled: true
    regions:
      - us-east-1
      - eu-west-1
    # Optional: Override credentials
    # access_key_id: ${AWS_ACCESS_KEY_ID}
    # secret_access_key: ${AWS_SECRET_ACCESS_KEY}
```

## What Gets Scanned

### Users
- User details (ARN, creation date, status)
- Access key last used timestamps
- MFA device status
- Group memberships
- User tags

### Policies
- Attached managed policies (AWS and customer)
- Inline user policies
- Group policies (attached + inline)
- Policy documents

### Permissions
- All permissions extracted from policies
- Permission scope calculation (read/write/admin)
- Wildcard detection

## Findings

### Excessive Permissions (Critical/High)
- Full wildcard policies (`*:*` on all resources)
- Service-level wildcards (`s3:*`, `ec2:*`)
- Excessive permission count (>50 by default)

### Dormant Accounts (High/Medium/Low)
- Accounts inactive for >90 days
- No access key usage
- Severity based on inactivity duration

### Missing MFA (High)
- Admin accounts without MFA enabled
- Privileged users without MFA

### Policy Violations
- Custom rule violations
- Compliance checks

## CLI Usage

```bash
# Basic AWS scan
accessaudit scan aws

# Scan specific region
accessaudit scan aws --region eu-west-1

# Scan without analysis
accessaudit scan aws --no-analyze

# Output to file
accessaudit scan aws --output report.json
```

## Programmatic Usage

```python
import asyncio
from accessaudit.connectors.aws import AWSConnector

async def scan_aws():
    connector = AWSConnector({
        "region": "us-east-1"
    })
    
    await connector.connect()
    
    # List all users
    accounts = await connector.list_accounts()
    print(f"Found {len(accounts)} users")
    
    # Get permissions for a user
    for account in accounts:
        perms = await connector.get_account_permissions(account.id)
        print(f"{account.username}: {len(perms)} permissions")
    
    await connector.disconnect()

asyncio.run(scan_aws())
```

## Multi-Region Scanning

To scan multiple regions:

```yaml
providers:
  aws:
    regions:
      - us-east-1
      - us-west-2
      - eu-west-1
      - ap-southeast-1
```

Or via CLI:

```bash
for region in us-east-1 us-west-2 eu-west-1; do
    accessaudit scan aws --region $region --output report-$region.json
done
```

## Limitations

- Does not scan IAM roles (coming in v0.2.0)
- Does not analyze resource-based policies
- Service control policies (SCPs) not yet supported
- Cross-account access analysis not yet supported

## Troubleshooting

### "NoCredentialsError"

AWS credentials not found. Check:
1. Environment variables are set
2. AWS CLI profile exists
3. IAM role is attached (if using EC2/ECS)

### "AccessDenied"

Missing IAM permissions. Ensure your user/role has the required IAM permissions listed in the Getting Started guide.

### Slow Scans

Large accounts (>100 users) may take several minutes. Tips:
- Use IAM roles (faster than access keys)
- Scan during off-peak hours
- Consider scanning specific regions only
