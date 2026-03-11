# AccessAudit Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    CLI / Web Dashboard                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                      API Layer (FastAPI)                     │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ Auth Manager │  │ Rate Limiter │  │  Audit Logger   │   │
│  └──────────────┘  └──────────────┘  └─────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core Services Layer                       │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │   Scan       │  │  Analysis    │  │   Reporting     │   │
│  │  Orchestrator│  │   Engine     │  │    Engine       │   │
│  └──────────────┘  └──────────────┘  └─────────────────┘   │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Connector Layer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ AWS IAM      │  │  Azure AD    │  │   GCP IAM       │   │
│  │ Connector    │  │  Connector   │  │   Connector     │   │
│  └──────────────┘  └──────────────┘  └─────────────────┘   │
│  ┌──────────────┐                                           │
│  │ SailPoint    │  [Plugin System for extensibility]        │
│  │ Connector    │                                           │
│  └──────────────┘                                           │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                    Data Layer                                │
│  ┌──────────────┐  ┌──────────────┐                         │
│  │ PostgreSQL   │  │  Redis       │                         │
│  │ (Audit Data) │  │  (Cache)     │                         │
│  └──────────────┘  └──────────────┘                         │
└─────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
accessaudit/
├── src/
│   ├── accessaudit/
│   │   ├── __init__.py
│   │   ├── core/              # Core business logic
│   │   │   ├── __init__.py
│   │   │   ├── scanner.py     # Scan orchestrator
│   │   │   ├── analyzer.py    # Analysis engine
│   │   │   └── reporter.py    # Report generation
│   │   ├── connectors/        # IAM provider connectors
│   │   │   ├── __init__.py
│   │   │   ├── base.py        # Base connector interface
│   │   │   ├── aws.py         # AWS IAM
│   │   │   ├── azure.py       # Azure AD
│   │   │   ├── gcp.py         # GCP IAM
│   │   │   └── sailpoint.py   # SailPoint IIQ
│   │   ├── models/            # Data models
│   │   │   ├── __init__.py
│   │   │   ├── account.py     # Account model
│   │   │   ├── permission.py  # Permission model
│   │   │   ├── policy.py      # Policy model
│   │   │   └── finding.py     # Finding/issue model
│   │   ├── analysis/          # Analysis modules
│   │   │   ├── __init__.py
│   │   │   ├── permissions.py # Permission analyzer
│   │   │   ├── dormant.py     # Dormant account detection
│   │   │   ├── anomaly.py     # ML-based anomaly detection
│   │   │   └── rules.py       # Policy rule engine
│   │   ├── api/               # FastAPI application
│   │   │   ├── __init__.py
│   │   │   ├── main.py        # FastAPI app
│   │   │   ├── routes/        # API routes
│   │   │   └── middleware/    # Auth, rate limiting
│   │   ├── cli/               # CLI application
│   │   │   ├── __init__.py
│   │   │   └── main.py        # CLI entrypoint
│   │   ├── db/                # Database layer
│   │   │   ├── __init__.py
│   │   │   ├── models.py      # SQLAlchemy models
│   │   │   └── repository.py  # Data access layer
│   │   └── utils/             # Utilities
│   │       ├── __init__.py
│   │       ├── config.py      # Configuration management
│   │       └── logging.py     # Logging setup
├── tests/                     # Test suite
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── dashboard/                 # React frontend (Phase 2)
│   ├── src/
│   ├── public/
│   └── package.json
├── docs/                      # Documentation
│   ├── getting-started.md
│   ├── connectors.md
│   └── api-reference.md
├── examples/                  # Example configs
│   ├── aws-scan.yaml
│   └── policy-rules.yaml
├── docker/                    # Docker configs
│   ├── Dockerfile
│   └── docker-compose.yml
├── .github/                   # GitHub workflows
│   └── workflows/
│       └── ci.yml
├── pyproject.toml            # Project metadata
├── README.md
├── LICENSE
└── .gitignore
```

## Data Models

### Account
```python
class Account:
    id: str
    provider: str  # aws, azure, gcp, sailpoint
    username: str
    email: Optional[str]
    created_at: datetime
    last_login: Optional[datetime]
    status: str  # active, inactive, disabled
    permissions: List[Permission]
    metadata: Dict
```

### Permission
```python
class Permission:
    id: str
    account_id: str
    resource_type: str  # s3, ec2, user, group, role
    resource_arn: str
    actions: List[str]
    effect: str  # allow, deny
    scope: str  # read, write, admin
```

### Finding
```python
class Finding:
    id: str
    severity: str  # critical, high, medium, low
    category: str  # excessive_permissions, dormant_account, policy_violation
    account_id: str
    title: str
    description: str
    remediation: str
    detected_at: datetime
```

## API Endpoints (MVP)

```
POST   /api/v1/scans              # Trigger a new scan
GET    /api/v1/scans/:id          # Get scan status
GET    /api/v1/scans/:id/report   # Get scan report
GET    /api/v1/findings           # List findings (with filters)
GET    /api/v1/accounts           # List accounts
GET    /api/v1/accounts/:id       # Get account details
```

## Configuration Format

```yaml
# config.yaml
providers:
  aws:
    enabled: true
    regions:
      - us-east-1
      - eu-west-1
    credentials:
      access_key_id: ${AWS_ACCESS_KEY_ID}
      secret_access_key: ${AWS_SECRET_ACCESS_KEY}
  
  azure:
    enabled: false
    tenant_id: ${AZURE_TENANT_ID}
    client_id: ${AZURE_CLIENT_ID}
    client_secret: ${AZURE_CLIENT_SECRET}

analysis:
  dormant_threshold_days: 90
  max_permissions_threshold: 50
  
  rules:
    - name: "No wildcard admin policies"
      severity: critical
      condition: "policy.actions contains '*' AND policy.resources contains '*'"
    
    - name: "MFA required for privileged accounts"
      severity: high
      condition: "account.has_admin_role AND NOT account.mfa_enabled"

reporting:
  formats:
    - json
    - pdf
  include_remediation: true
```

## Security Considerations

1. **Credentials Storage**
   - Never store credentials in code
   - Use environment variables or secret managers (AWS Secrets Manager, Azure Key Vault)
   - Support IAM roles for AWS (preferred over access keys)

2. **Least Privilege**
   - Document minimum required permissions for each connector
   - Provide CloudFormation/Terraform templates for IAM policies

3. **Audit Logging**
   - Log all scans and API requests
   - Track who triggered scans and when

4. **Data Protection**
   - Encrypt sensitive data at rest (PostgreSQL encryption)
   - Use TLS for API communication
   - Support data retention policies

## Performance Targets

- Scan 1000 AWS IAM users in <3 minutes
- Scan 5000 permissions in <1 minute
- API response time <500ms (p95)
- Support concurrent scans (up to 5 providers simultaneously)

## Deployment

### Docker Compose (Development)
```bash
docker-compose up -d
```

### Kubernetes (Production)
- Helm chart provided
- Horizontal pod autoscaling
- Persistent volumes for PostgreSQL
- Redis cluster for caching

---

**Next Steps for Implementation:**
1. Set up Python project structure (pyproject.toml, virtual env)
2. Implement base connector interface
3. Build AWS IAM connector (boto3)
4. Create core analysis modules
5. Build CLI tool
6. Add unit tests
7. Docker packaging
