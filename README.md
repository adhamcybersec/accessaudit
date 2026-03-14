# AccessAudit

> **IAM Access Review Automation Platform**
> Intelligent, multi-provider identity and access management auditing for security teams.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/adhamcybersec/accessaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/adhamcybersec/accessaudit/actions/workflows/ci.yml)
[![GitHub Issues](https://img.shields.io/github/issues/adhamcybersec/accessaudit)](https://github.com/adhamcybersec/accessaudit/issues)
[![GitHub Stars](https://img.shields.io/github/stars/adhamcybersec/accessaudit)](https://github.com/adhamcybersec/accessaudit/stargazers)

---

## What is AccessAudit?

AccessAudit automates IAM security audits across AWS, Azure, GCP, and SailPoint. It detects excessive permissions, dormant accounts, policy violations, and access anomalies — helping security teams maintain least-privilege and meet compliance requirements.

### Key Features

- **Multi-Provider Support** - AWS IAM, Azure AD, GCP IAM, SailPoint IIQ (SCIM 2.0)
- **Intelligent Analysis** - ML-based anomaly detection (Isolation Forest), policy violation scanning
- **OPA/Rego Policy Engine** - Policy-as-code with built-in SOC 2, ISO 27001, and CIS AWS rule packs
- **Compliance Reports** - HTML and PDF reports for SOC 2, ISO 27001, CIS AWS Foundations
- **Persistent Storage** - PostgreSQL for audit data, Redis for caching, with in-memory fallback
- **Authentication** - JWT + API key auth with opt-in enforcement
- **Scheduled Scans** - Cron-based recurring scans with auto-analysis
- **Notifications** - Slack, Microsoft Teams, and generic webhook providers
- **Remediation Automation** - Approval-gated actions with state machine and rollback
- **Web Dashboard** - HTMX-powered dashboard for scans, findings, schedules, and remediation
- **REST API** - Full FastAPI backend with 40+ endpoints
- **CLI Tool** - Typer-based CLI for scan, analyze, report, and serve
- **Open Source** - MIT licensed, community-driven

---

## Quick Start

### Installation

```bash
# From source
git clone https://github.com/adhamcybersec/accessaudit.git
cd accessaudit
pip install -e .

# With optional cloud provider extras
pip install -e ".[azure]"    # Azure AD support
pip install -e ".[gcp]"      # GCP IAM support
pip install -e ".[all]"      # All providers
```

### AWS IAM Scan

```bash
# Configure AWS credentials
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Run a scan with auto-analysis
accessaudit scan aws --output report.json

# View findings
accessaudit findings list --severity critical
```

### SailPoint IIQ Scan

```bash
accessaudit scan sailpoint \
  --base-url https://iiq.company.com/identityiq \
  --username spadmin \
  --password admin
```

### Web Dashboard

```bash
# Start the API server + dashboard
accessaudit serve --host 0.0.0.0 --port 8000

# Visit http://localhost:8000
```

### With Persistence (PostgreSQL + Redis)

```bash
# Set environment variables for persistent storage
export DATABASE_URL="postgresql+asyncpg://accessaudit:password@localhost:5432/accessaudit"
export REDIS_URL="redis://localhost:6379/0"
export AUTH_SECRET_KEY="your-secret-key-at-least-32-chars"

# Run migrations
alembic upgrade head

# Start the server (now with persistent storage + auth)
accessaudit serve
```

### Docker Compose

```bash
# Start full stack (app + PostgreSQL + Redis)
docker compose -f docker/docker-compose.yml up -d

# Run migrations
docker compose -f docker/docker-compose.yml exec accessaudit alembic upgrade head
```

---

## API Endpoints

The REST API is available when running `accessaudit serve`.

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check with component status |
| `/api/v1/scans` | POST | Start a new scan (aws, azure, gcp, sailpoint) |
| `/api/v1/scans` | GET | List all scans |
| `/api/v1/scans/{scan_id}` | GET | Get scan details |
| `/api/v1/scans/{scan_id}/findings` | GET | Get findings for a scan |
| `/api/v1/analyze/{scan_id}` | POST | Run analysis on a scan |
| `/api/v1/reports/{scan_id}` | GET | Generate report (json, html, pdf) |
| `/api/v1/rules` | GET | List OPA/Rego rules |
| `/api/v1/rules/validate` | POST | Validate a Rego policy |

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/register` | POST | Register new user |
| `/api/v1/auth/login` | POST | Login (returns JWT + API key) |
| `/api/v1/auth/me` | GET | Get current user info |
| `/api/v1/auth/rotate-key` | POST | Rotate API key |

### Scheduled Scans

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/schedules` | GET/POST | List/create scheduled scans |
| `/api/v1/schedules/{id}` | GET/PUT/DELETE | Manage a schedule |
| `/api/v1/schedules/{id}/enable` | POST | Enable schedule |
| `/api/v1/schedules/{id}/disable` | POST | Disable schedule |
| `/api/v1/schedules/{id}/runs` | GET | View run history |

### Notifications

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/notifications/config` | GET/PUT | View/update notification config |
| `/api/v1/notifications/test` | POST | Send test notification |
| `/api/v1/notifications/history` | GET | View notification history |

### Remediation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/remediations` | GET | List remediation actions |
| `/api/v1/remediations/suggest/{scan_id}` | POST | Generate suggestions from findings |
| `/api/v1/remediations/{id}` | GET | Get action details |
| `/api/v1/remediations/{id}/approve` | POST | Approve action |
| `/api/v1/remediations/{id}/reject` | POST | Reject action |
| `/api/v1/remediations/{id}/execute` | POST | Execute approved action |
| `/api/v1/remediations/{id}/rollback` | POST | Rollback completed action |
| `/api/v1/remediations/bulk-approve` | POST | Bulk approve actions |

### Dashboard

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard home |
| `/scans` | GET | Scans page |
| `/findings` | GET | Findings page |
| `/reports` | GET | Reports page |
| `/schedules` | GET | Schedules page |
| `/notifications-dashboard` | GET | Notifications page |
| `/remediation-dashboard` | GET | Remediation page |
| `/rules-dashboard` | GET | Rules page |

---

## Compliance Reports

AccessAudit generates HTML and PDF compliance reports mapped to industry frameworks:

- **SOC 2** - Trust Services Criteria (CC6.1, CC6.2, CC6.3, etc.)
- **ISO 27001** - Annex A controls (A.9.1, A.9.2, A.9.4, etc.)
- **CIS AWS Foundations** - CIS Benchmark controls

```bash
# Generate reports after scanning
accessaudit report generate --format html --template soc2
accessaudit report generate --format pdf --template iso27001
```

---

## Supported Providers

| Provider | Status | Features |
|----------|--------|----------|
| AWS IAM | Complete | Users, roles, policies, permissions |
| Azure AD | Complete | Users, groups, roles, RBAC, MFA status |
| GCP IAM | Complete | Service accounts, roles, bindings |
| SailPoint IIQ | Complete | SCIM 2.0 users, entitlements, roles |

---

## Detection Capabilities

### Excessive Permissions
- Detects users/roles with wildcard policies (`*`)
- Identifies admin-level access without MFA
- Flags overly permissive resource policies

### Dormant Accounts
- Tracks last login/usage timestamps
- Identifies accounts inactive for >90 days (configurable)
- Recommends deactivation

### Policy Violations
- Custom rule engine (policy-as-code with OPA/Rego)
- Compliance checks (SOC 2, ISO 27001, CIS Benchmarks)
- Anomaly detection via ML (Isolation Forest)

### Remediation Automation
- Auto-generates remediation suggestions from findings
- Approval-gated state machine: PENDING -> APPROVED -> EXECUTING -> COMPLETED
- Supported actions: remove_policy, disable_account, enable_mfa, reduce_permissions, rotate_credentials
- Rollback support for completed actions
- Bulk approve capability

---

## Architecture

```
                    +------------------+
                    |   CLI (Typer)    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |  FastAPI + Auth   |
                    +--------+---------+
                             |
          +------------------+------------------+
          |                  |                  |
+---------v------+ +--------v--------+ +-------v--------+
| Scan Orchestrator| |Analysis Engine | |Report Generator|
+--------+-------+ +--------+--------+ +-------+--------+
         |                  |                   |
+--------v-------+  +------v-------+    +------v--------+
| Connectors     |  | ML Anomaly   |    | Jinja2/PDF    |
| AWS, Azure,    |  | Permissions  |    | SOC2, ISO     |
| GCP, SailPoint |  | Dormant, OPA |    +---------------+
+----------------+  +--------------+
         |
+--------v-----------------+
| Storage (Postgres/Memory)|
| Cache (Redis/None)       |
+--------------------------+
```

---

## Configuration

```yaml
providers:
  aws:
    enabled: true
    regions: [us-east-1, eu-west-1]
  sailpoint:
    enabled: false
    base_url: https://iiq.company.com/identityiq

analysis:
  dormant_threshold_days: 90
  max_permissions_threshold: 50

# Optional: persistent storage
database:
  url: postgresql+asyncpg://accessaudit:password@localhost:5432/accessaudit

# Optional: caching
redis:
  url: redis://localhost:6379/0

# Optional: authentication
auth:
  secret_key: your-secret-key
  require_auth: false

# Optional: notifications
notifications:
  enabled: true
  providers:
    - type: slack
      webhook_url: https://hooks.slack.com/services/...
      min_severity: medium
      events: [scan_completed, critical_finding]
```

Environment variables override config: `DATABASE_URL`, `REDIS_URL`, `AUTH_SECRET_KEY`, `AWS_ACCESS_KEY_ID`, etc.

---

## Development

### Setup

```bash
git clone https://github.com/adhamcybersec/accessaudit.git
cd accessaudit
python3.11 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

### Run Tests

```bash
# Unit tests
pytest tests/unit/ -v

# With coverage
pytest tests/unit/ -v --cov=accessaudit

# Integration tests (requires Docker services)
docker compose -f docker/docker-compose.yml up -d postgres redis
export DATABASE_URL="postgresql+asyncpg://accessaudit:accessaudit_dev@localhost:5432/accessaudit"
export REDIS_URL="redis://localhost:6379/0"
alembic upgrade head
pytest tests/integration/ -v
```

### Linting

```bash
black --check src/ tests/
ruff check src/ tests/
mypy src/ --ignore-missing-imports
```

### Project Structure

```
src/accessaudit/
├── api/               # FastAPI app, routes, templates
│   ├── routes/        # API + HTMX dashboard routes
│   └── templates/     # Jinja2 + Tailwind CSS templates
├── auth/              # JWT + API key authentication
├── cli/               # Typer CLI tool
├── connectors/        # IAM provider integrations (AWS, Azure, GCP, SailPoint)
├── core/              # Scanner, analyzer, reporter
│   └── compliance/    # SOC 2, ISO 27001 mappings
├── db/                # SQLAlchemy models, repository, migrations
│   └── migrations/    # Alembic async migrations
├── models/            # Pydantic data models
├── analysis/          # Detection algorithms (permissions, dormant, anomaly, OPA)
├── notifications/     # Slack, Teams, webhook providers
├── remediation/       # Approval-gated remediation engine
├── scheduling/        # Cron-based scheduled scans
├── services/          # Storage abstraction layer
└── utils/             # Config, logging
```

---

## Contributing

Contributions welcome! Please open an issue or pull request.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

Built with inspiration from:
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [Prowler](https://github.com/prowler-cloud/prowler)
- [CloudCustodian](https://github.com/cloud-custodian/cloud-custodian)

---

**Project Status:** Phase 3 complete (persistence, auth, SailPoint, notifications, scheduling, remediation)
**Maintainer:** Adham Rashed ([@adhamcybersec](https://github.com/adhampx))
**Start Date:** March 2026
