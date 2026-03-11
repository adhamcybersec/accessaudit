# Configuration Reference

AccessAudit can be configured via YAML file, environment variables, or CLI flags.

## Configuration File

Create `config.yaml` in your working directory:

```yaml
# AccessAudit Configuration

providers:
  aws:
    enabled: true
    regions:
      - us-east-1
    # Credentials (optional - uses environment/IAM role by default)
    # access_key_id: ${AWS_ACCESS_KEY_ID}
    # secret_access_key: ${AWS_SECRET_ACCESS_KEY}

  azure:
    enabled: false
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}

  gcp:
    enabled: false
    project_id: ${GOOGLE_CLOUD_PROJECT}
    credentials_file: ${GOOGLE_APPLICATION_CREDENTIALS}

analysis:
  # Days of inactivity before marking account as dormant
  dormant_threshold_days: 90
  
  # Number of permissions before flagging as excessive
  max_permissions_threshold: 50
  
  # Custom compliance rules
  rules:
    - name: "No wildcard admin policies"
      severity: critical
      condition: "policy.is_overly_permissive"
      description: "Policies should not grant wildcard permissions"
      remediation: "Replace with least-privilege policy"
    
    - name: "MFA required for admins"
      severity: high
      condition: "account.has_admin_role AND NOT account.mfa_enabled"
      description: "Admin accounts must have MFA enabled"
      remediation: "Enable MFA for this account"

reporting:
  formats:
    - json
  include_remediation: true
  output_dir: ./reports
```

## Environment Variables

All configuration can be overridden via environment variables:

```bash
# AWS
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"

# Azure
export AZURE_TENANT_ID="..."
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."

# GCP
export GOOGLE_CLOUD_PROJECT="..."
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials.json"

# AccessAudit settings
export ACCESSAUDIT_ANALYSIS__DORMANT_THRESHOLD_DAYS=90
export ACCESSAUDIT_REPORTING__OUTPUT_DIR="./reports"
```

## CLI Flags

Common CLI options:

```bash
# Use specific config file
accessaudit --config /path/to/config.yaml scan aws

# Enable verbose logging
accessaudit --verbose scan aws

# Show version
accessaudit --version
```

## Configuration Options

### providers.aws

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `true` | Enable AWS scanning |
| `regions` | list | `["us-east-1"]` | AWS regions to scan |
| `access_key_id` | string | - | AWS access key (optional) |
| `secret_access_key` | string | - | AWS secret key (optional) |
| `profile` | string | - | AWS CLI profile name |

### providers.azure

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable Azure scanning |
| `tenant_id` | string | - | Azure AD tenant ID |
| `client_id` | string | - | Application client ID |
| `client_secret` | string | - | Application secret |

### providers.gcp

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | `false` | Enable GCP scanning |
| `project_id` | string | - | GCP project ID |
| `credentials_file` | string | - | Path to service account JSON |

### analysis

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `dormant_threshold_days` | int | `90` | Days before account is dormant |
| `max_permissions_threshold` | int | `50` | Excessive permission count |
| `rules` | list | `[]` | Custom compliance rules |

### analysis.rules[]

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `name` | string | Yes | Rule name |
| `severity` | string | Yes | `critical`, `high`, `medium`, `low` |
| `condition` | string | Yes | Rule condition expression |
| `description` | string | No | Rule description |
| `remediation` | string | No | Remediation guidance |

### reporting

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `formats` | list | `["json"]` | Output formats |
| `include_remediation` | bool | `true` | Include fix guidance |
| `output_dir` | string | `./reports` | Report output directory |

## Rule Conditions

Available conditions for custom rules:

### Account Conditions
- `account.has_admin_role` - Account has admin privileges
- `account.mfa_enabled` - MFA is enabled

### Policy Conditions
- `policy.has_wildcard_actions` - Policy has wildcard actions
- `policy.has_wildcard_resources` - Policy has wildcard resources
- `policy.is_overly_permissive` - Wildcard actions AND resources

### Permission Conditions
- `permission.is_wildcard` - Permission has wildcard
- `permission.actions contains '*'` - Actions include wildcard

### Logical Operators
- `AND` - Both conditions must be true
- `OR` - Either condition must be true
- `NOT` - Negate condition

Example:
```yaml
condition: "account.has_admin_role AND NOT account.mfa_enabled"
```

## Precedence

Configuration is loaded in this order (later overrides earlier):

1. Default values
2. Configuration file (`config.yaml`)
3. Environment variables
4. CLI flags
