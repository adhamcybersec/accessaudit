# AccessAudit

> **IAM Access Review Automation Platform**  
> Intelligent, multi-provider identity and access management auditing for security teams.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/adhamcybersec/accessaudit/actions/workflows/ci.yml/badge.svg)](https://github.com/adhamcybersec/accessaudit/actions/workflows/ci.yml)
[![GitHub Issues](https://img.shields.io/github/issues/adhamcybersec/accessaudit)](https://github.com/adhamcybersec/accessaudit/issues)
[![GitHub Stars](https://img.shields.io/github/stars/adhamcybersec/accessaudit)](https://github.com/adhamcybersec/accessaudit/stargazers)

---

## 🎯 What is AccessAudit?

AccessAudit automates IAM security audits across AWS, Azure, GCP, and SailPoint. It detects excessive permissions, dormant accounts, policy violations, and access anomalies—helping security teams maintain least-privilege and meet compliance requirements.

### Key Features

- ✅ **Multi-Provider Support** - AWS IAM, Azure AD, GCP IAM, SailPoint IIQ
- ✅ **Intelligent Analysis** - ML-based anomaly detection (Isolation Forest), policy violation scanning
- ✅ **OPA/Rego Policy Engine** - Policy-as-code with built-in SOC 2, ISO 27001, and CIS AWS rule packs
- ✅ **Compliance Reports** - HTML and PDF reports for SOC 2, ISO 27001, CIS AWS Foundations
- ✅ **Web Dashboard** - HTMX-powered dashboard for scans, findings, reports, and rules
- ✅ **REST API** - Full FastAPI backend with scan, analyze, report, and rule endpoints
- ✅ **Developer-Friendly** - CLI tool, REST API, policy-as-code
- ✅ **Open Source** - MIT licensed, community-driven

---

## 🚀 Quick Start

### Installation

```bash
# From PyPI (when published)
pip install accessaudit

# With optional cloud provider extras
pip install accessaudit[azure]    # Azure AD support
pip install accessaudit[gcp]      # GCP IAM support
pip install accessaudit[all]      # All providers

# From source
git clone https://github.com/adhamcybersec/accessaudit.git
cd accessaudit
pip install -e .
```

### AWS IAM Scan (Example)

```bash
# Configure AWS credentials
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

# Run a scan
accessaudit scan aws --output report.json

# View findings
accessaudit findings list --severity critical
```

### Web Dashboard

```bash
# Start the HTMX web dashboard (served by FastAPI)
accessaudit serve --host 0.0.0.0 --port 8000

# Visit http://localhost:8000 for the dashboard
```

### Configuration

Create `config.yaml`:

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
      condition: "policy.actions contains '*' AND policy.resources contains '*'"
```

---

## 🌐 API Endpoints

The REST API is available when running `accessaudit serve`.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Health check |
| `/api/v1/scans` | POST | Start a new scan |
| `/api/v1/scans` | GET | List all scans |
| `/api/v1/scans/{scan_id}` | GET | Get scan details |
| `/api/v1/scans/{scan_id}/findings` | GET | Get findings for a scan |
| `/api/v1/analyze/{scan_id}` | POST | Run analysis on a scan |
| `/api/v1/reports/{scan_id}` | GET | Generate a compliance report |
| `/api/v1/rules` | GET | List OPA/Rego rules |
| `/api/v1/rules/validate` | POST | Validate a Rego policy |
| `/` | GET | HTMX web dashboard |

---

## 📝 Compliance Reports

AccessAudit generates HTML and PDF compliance reports mapped to industry frameworks:

- **SOC 2** - Trust Services Criteria (CC6.1, CC6.2, CC6.3, etc.)
- **ISO 27001** - Annex A controls (A.9.1, A.9.2, A.9.4, etc.)
- **CIS AWS Foundations** - CIS Benchmark controls (1.1-1.22, etc.)

```bash
# Generate a compliance report after scanning
accessaudit report generate --format html --framework soc2
accessaudit report generate --format pdf --framework iso27001
```

---

## 📐 Policy Engine (OPA/Rego)

AccessAudit includes an OPA/Rego-based policy engine with built-in rule packs:

- `rules/base.rego` - Core access control rules
- `rules/soc2.rego` - SOC 2 compliance rules
- `rules/iso27001.rego` - ISO 27001 compliance rules
- `rules/cis_aws.rego` - CIS AWS Foundations Benchmark rules

Custom rules can be added to the `rules/` directory in Rego format. The policy engine evaluates findings against all enabled rule packs during analysis.

---

## 📋 Supported Providers

| Provider | Status | Features |
|----------|--------|----------|
| AWS IAM | ✅ Complete | Users, roles, policies, permissions |
| Azure AD | ✅ Complete | Users, groups, roles, permissions |
| GCP IAM | ✅ Complete | Service accounts, roles, bindings |
| SailPoint IIQ | 🚧 Phase 3 | Identity governance, access reviews |

---

## 🏗️ Architecture

```
CLI / API → Scan Orchestrator → Connectors (AWS/Azure/GCP)
                ↓
         Analysis Engine → Findings → Reports
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design.

---

## 🔍 Detection Capabilities

### Excessive Permissions
- Detects users/roles with wildcard policies (`*`)
- Identifies admin-level access without MFA
- Flags overly permissive resource policies

### Dormant Accounts
- Tracks last login/usage timestamps
- Identifies accounts inactive for >90 days
- Recommends deactivation

### Policy Violations
- Custom rule engine (policy-as-code)
- Compliance checks (SOC 2, ISO 27001, CIS Benchmarks)
- Anomaly detection via ML

---

## 🛠️ Development

### Setup

```bash
# Clone repo
git clone https://github.com/adhamcybersec/accessaudit.git
cd accessaudit

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linters
black src/ tests/
ruff check src/ tests/
mypy src/
```

### Project Structure

```
src/accessaudit/
├── core/              # Business logic (scanner, analyzer, reporter)
│   └── compliance/    # SOC 2, ISO 27001 compliance mappings
├── connectors/        # IAM provider integrations (AWS, Azure, GCP)
├── models/            # Data models (accounts, policies, findings)
├── analysis/          # Detection algorithms (permissions, dormant, anomaly, policy engine)
├── api/               # FastAPI application
│   └── routes/        # API + HTMX dashboard routes
├── cli/               # CLI tool (Typer)
└── utils/             # Config management, logging
rules/                 # OPA/Rego policy rule packs
```

---

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📜 License

MIT License - see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

Built with inspiration from:
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [Prowler](https://github.com/prowler-cloud/prowler)
- [CloudCustodian](https://github.com/cloud-custodian/cloud-custodian)

---

**Project Status:** 🚧 Phase 2 complete, Phase 3 in planning
**Maintainer:** Adham Rashed ([@adhamcybersec](https://github.com/adhampx))  
**Start Date:** March 2026
