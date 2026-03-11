# AccessAudit - IAM Access Review Automation Platform

## Vision
An intelligent, automated platform for Identity and Access Management (IAM) auditing across multiple cloud providers and identity systems. Helps security teams detect excessive permissions, dormant accounts, policy violations, and access anomalies before they become security incidents.

## Problem Statement
- Manual IAM audits are time-consuming and error-prone
- Organizations struggle to maintain least-privilege across multiple platforms
- Dormant accounts and excessive permissions create security risks
- Compliance reporting (SOC 2, ISO 27001) requires continuous monitoring
- Most tools are vendor-locked or prohibitively expensive

## Solution
AccessAudit provides:
1. **Multi-provider integration** - AWS IAM, Azure AD, GCP IAM, SailPoint IIQ
2. **Intelligent analysis** - ML-based anomaly detection, policy violation scanning
3. **Automated reporting** - Compliance reports, risk scoring, remediation recommendations
4. **Developer-friendly** - CLI tool, API, policy-as-code framework
5. **Open source** - Community-driven, transparent, extensible

## Target Users
- Security teams in mid-to-large organizations
- DevSecOps engineers
- Compliance officers
- Cloud security consultants

## Tech Stack
- **Backend:** Python 3.11+ (FastAPI for API, asyncio for concurrent IAM queries)
- **Analysis Engine:** scikit-learn for ML, pandas for data processing
- **Storage:** PostgreSQL for audit data, Redis for caching
- **Frontend:** React + TypeScript (dashboard)
- **CLI:** Click/Typer
- **Deployment:** Docker, Kubernetes-ready

## Architecture

### Core Components

1. **Connector Layer**
   - AWS IAM Connector (boto3)
   - Azure AD Connector (msal, msgraph)
   - GCP IAM Connector (google-cloud-iam)
   - SailPoint Connector (REST API)
   - Extensible plugin system

2. **Analysis Engine**
   - Permission analyzer (detect over-privileged accounts)
   - Dormant account detector (last-used tracking)
   - Policy violation scanner (custom rules)
   - Anomaly detection (ML model for unusual access patterns)

3. **Reporting Engine**
   - Compliance report generator
   - Risk scoring algorithm
   - Remediation recommendations
   - Export to PDF/JSON/CSV

4. **API Layer**
   - RESTful API (FastAPI)
   - Authentication (OAuth2 + API keys)
   - Rate limiting
   - Audit logging

5. **CLI Tool**
   - Scan commands
   - Report generation
   - CI/CD integration
   - Config management

6. **Web Dashboard**
   - Real-time audit status
   - Risk visualization
   - Policy management
   - User/role explorer

## MVP Features (Phase 1)

1. ✅ AWS IAM connector
2. ✅ Permission analysis (detect over-privileged)
3. ✅ Dormant account detection
4. ✅ Basic CLI tool
5. ✅ JSON report output
6. ✅ Docker deployment

## Phase 2 Features

- Azure AD + GCP connectors
- ML-based anomaly detection
- Web dashboard
- Compliance report templates
- Policy-as-code framework

## Phase 3 Features

- SailPoint IIQ integration
- Slack/Teams notifications
- Scheduled scans
- Remediation automation (with approval workflow)

## Success Metrics

- Detects 90%+ of common IAM misconfigurations
- Scans 1000+ accounts in <5 minutes
- <5% false positive rate for anomaly detection
- GitHub stars, community contributions

## License
MIT License (permissive, enterprise-friendly)

---

**Project Start:** 2026-03-11
**Lead:** Davis (Architecture, PM)
**Developer:** Claude Code (Implementation)
