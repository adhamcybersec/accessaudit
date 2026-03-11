# Getting Started with AccessAudit

AccessAudit is an IAM access review automation platform that helps security teams detect excessive permissions, dormant accounts, and policy violations across AWS, Azure, and GCP.

## Installation

### From PyPI (Coming Soon)

```bash
pip install accessaudit
```

### From Source

```bash
git clone https://github.com/adhampx/accessaudit.git
cd accessaudit
pip install -e .
```

### Using Docker

```bash
docker pull ghcr.io/adhampx/accessaudit:latest
docker run accessaudit --help
```

## Quick Start

### 1. Configure AWS Credentials

AccessAudit uses standard AWS credential sources:

```bash
# Option 1: Environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Option 2: AWS CLI profile
export AWS_PROFILE="your-profile"

# Option 3: IAM role (recommended for EC2/ECS)
# No configuration needed - uses instance metadata
```

### 2. Run Your First Scan

```bash
# Scan AWS IAM
accessaudit scan aws

# Scan with JSON output
accessaudit scan aws --output report.json
```

### 3. View Findings

```bash
# List all findings
accessaudit findings list

# Filter by severity
accessaudit findings list --severity critical

# Show details for a specific finding
accessaudit findings show finding-abc123
```

### 4. Generate Reports

```bash
# Generate JSON report
accessaudit report generate --output report.json

# Show summary
accessaudit report summary
```

## Configuration

Create a `config.yaml` file for advanced configuration:

```yaml
providers:
  aws:
    enabled: true
    regions:
      - us-east-1
      - eu-west-1

analysis:
  dormant_threshold_days: 90
  max_permissions_threshold: 50

  rules:
    - name: "No wildcard admin policies"
      severity: critical
      condition: "policy.is_overly_permissive"

reporting:
  formats:
    - json
  include_remediation: true
```

Run with config:

```bash
accessaudit --config config.yaml scan aws
```

## Required IAM Permissions

AccessAudit needs the following IAM permissions to scan AWS:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:GetUser",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListMFADevices",
        "iam:ListGroupsForUser",
        "iam:ListUserTags",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListEntitiesForPolicy",
        "iam:ListAttachedGroupPolicies",
        "iam:ListGroupPolicies",
        "iam:GetGroupPolicy"
      ],
      "Resource": "*"
    }
  ]
}
```

## Next Steps

- [AWS Connector Documentation](./aws-connector.md)
- [Configuration Reference](./configuration.md)
- [API Reference](./api-reference.md)
