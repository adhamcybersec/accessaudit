# AccessAudit

> **IAM Access Review Automation Platform**  
> Intelligent, multi-provider identity and access management auditing for security teams.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## 🎯 What is AccessAudit?

AccessAudit automates IAM security audits across AWS, Azure, GCP, and SailPoint. It detects excessive permissions, dormant accounts, policy violations, and access anomalies—helping security teams maintain least-privilege and meet compliance requirements.

### Key Features

- ✅ **Multi-Provider Support** - AWS IAM, Azure AD, GCP IAM, SailPoint IIQ
- ✅ **Intelligent Analysis** - ML-based anomaly detection, policy violation scanning
- ✅ **Automated Reporting** - Compliance reports (SOC 2, ISO 27001), risk scoring
- ✅ **Developer-Friendly** - CLI tool, REST API, policy-as-code
- ✅ **Open Source** - MIT licensed, community-driven

---

## 🚀 Quick Start

### Installation

```bash
# From PyPI (when published)
pip install accessaudit

# From source
git clone https://github.com/adhampx/accessaudit.git
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

## 📋 Supported Providers

| Provider | Status | Features |
|----------|--------|----------|
| AWS IAM | ✅ MVP | Users, roles, policies, permissions |
| Azure AD | 🚧 Phase 2 | Users, groups, roles, permissions |
| GCP IAM | 🚧 Phase 2 | Service accounts, roles, bindings |
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
git clone https://github.com/adhampx/accessaudit.git
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
├── core/          # Business logic
├── connectors/    # IAM provider integrations
├── models/        # Data models
├── analysis/      # Detection algorithms
├── api/           # FastAPI application
├── cli/           # CLI tool
└── db/            # Database layer
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

**Project Status:** 🚧 MVP in development  
**Maintainer:** Adham Rashed ([@adhampx](https://github.com/adhampx))  
**Start Date:** March 2026
