# Phase 2 Design: Full Feature Expansion

**Date:** 2026-03-11
**Status:** Approved
**Scope:** Azure AD + GCP connectors, ML anomaly detection, OPA policy engine, FastAPI + HTMX dashboard, compliance reports (HTML + PDF)

---

## Architecture Overview

```
                    +----------------------------+
                    |   HTMX + Jinja2 Dashboard  |
                    +--------------+-------------+
                                   |
                    +--------------v-------------+
                    |      FastAPI Server         |
                    |   (REST API + HTML views)   |
                    +--------------+-------------+
                                   |
          +------------------------+------------------------+
          |                        |                        |
+---------v--------+    +---------v--------+    +---------v--------+
| Scan Orchestrator|    | Analysis Engine  |    | Report Generator |
+--------+---------+    +--------+---------+    +--------+---------+
         |                       |                       |
    +----+----+            +-----+-----+           +-----+-----+
    |    |    |            |     |     |           |     |     |
   AWS Azure GCP       Perms Dormant  ML       JSON  HTML   PDF
                                |
                          Policy Engine
                          (OPA/Rego)
```

Key principle: Each new component plugs into existing interfaces. No database yet -- scan results stay in-memory/JSON. PostgreSQL persistence deferred to Phase 3.

---

## 1. Azure AD Connector

**SDK:** `msal` + Microsoft Graph API (Entra ID) + `azure-mgmt-authorization` (ARM RBAC)

**Scope:** Full coverage of both identity-level and resource-level permissions.

**Graph API coverage:**
- Users, groups, directory roles, app registrations, service principals
- Conditional access policies

**ARM RBAC coverage:**
- Subscription-level role assignments
- Custom role definitions

**Model mapping:**
- Azure AD users/service principals -> `Account`
- Directory roles + RBAC assignments -> `Permission`
- Conditional access policies + RBAC role definitions -> `Policy`

**Auth:** Client credential flow (tenant_id, client_id, client_secret)

**File:** `src/accessaudit/connectors/azure.py`

**New dependencies:** `msal>=1.26.0`, `azure-identity>=1.15.0`, `azure-mgmt-authorization>=4.0.0`, `msgraph-core>=1.0.0`

---

## 2. GCP IAM Connector

**SDK:** `google-cloud-iam` + `google-cloud-resource-manager`

**Coverage:**
- Service accounts, IAM members -> `Account`
- IAM bindings (role -> member mappings) -> `Permission`
- Predefined + custom roles -> `Policy`

**Auth:** Service account key JSON or application default credentials

**File:** `src/accessaudit/connectors/gcp.py`

**New dependencies:** `google-cloud-iam>=2.14.0`, `google-auth>=2.27.0`, `google-cloud-resource-manager>=1.12.0`

---

## 3. BaseConnector ABC Update

Add optional `list_roles()` method for Azure/GCP role concepts:

```python
async def list_roles(self) -> list[Policy]:
    """Optional: List roles (Azure/GCP). Defaults to empty."""
    return []
```

---

## 4. ML Anomaly Detection

**Approach:** Permission structure outlier detection using Isolation Forest (scikit-learn).

**Feature extraction per account:**
- Number of permissions per service
- Permission scope distribution (% read / % write / % admin)
- Number of groups, MFA enabled, account age
- Number of attached policies, inline vs managed ratio

**Peer grouping:** Accounts grouped by their groups/roles. Anomalies are relative to peers.

**Minimum data:** 10 accounts per peer group. Below threshold, skip group with warning.

**New files:**
- `src/accessaudit/analysis/anomaly.py` - AnomalyDetector class
- `src/accessaudit/analysis/features.py` - Feature extraction

**Integration:** Plugs into `Analyzer` orchestrator alongside existing analyzers. Returns `Finding` objects with `category=FindingCategory.ANOMALY`.

---

## 5. Policy Engine (OPA/Rego)

**Approach:** Subprocess to OPA binary for full Rego compatibility.

**User-facing:** Users write `.rego` policy files evaluated against scan data as JSON input.

**Built-in rule packs:**
- `rules/base.rego` - Default security rules
- `rules/soc2.rego` - SOC 2 compliance rules
- `rules/iso27001.rego` - ISO 27001 rules
- `rules/cis_aws.rego` - CIS AWS Benchmark rules

**Migration:** Old YAML `RuleEngine` stays as fallback. Converter available for YAML -> Rego.

**New file:** `src/accessaudit/analysis/policy_engine.py`

---

## 6. FastAPI Server

**API endpoints:**

```
POST /api/v1/scans              - Trigger a scan
GET  /api/v1/scans              - List past scans
GET  /api/v1/scans/{id}         - Get scan result
GET  /api/v1/scans/{id}/findings - Get findings for a scan
POST /api/v1/analyze/{scan_id}  - Run analysis on scan result
GET  /api/v1/reports/{scan_id}  - Generate/download report
GET  /api/v1/rules              - List policy rules
POST /api/v1/rules/validate     - Validate a Rego policy
GET  /api/v1/health             - Health check
```

Scans run via `asyncio.create_task()` -- POST returns scan ID, client polls.

**New files:**
- `src/accessaudit/api/app.py` - FastAPI app factory
- `src/accessaudit/api/routes/scans.py`
- `src/accessaudit/api/routes/findings.py`
- `src/accessaudit/api/routes/reports.py`
- `src/accessaudit/api/routes/rules.py`
- `src/accessaudit/api/routes/dashboard.py`

---

## 7. HTMX + Jinja2 Dashboard

**Pages:**

```
GET /                    - Dashboard home (scan summary, recent findings)
GET /scans               - Scan history, trigger new scan
GET /scans/{id}          - Scan detail
GET /findings            - All findings (filterable)
GET /findings/{id}       - Finding detail with remediation
GET /reports             - Generate/download compliance reports
GET /rules               - View/upload policy rules
```

**Interactivity via HTMX:**
- Filtering findings table without full page reload
- Polling scan status while running
- Inline expanding finding details

**Styling:** Tailwind CSS via CDN. No build step.

**Template files:** `src/accessaudit/api/templates/`

---

## 8. Compliance Reports (HTML + PDF)

**Frameworks:**
- SOC 2 (Trust Services Criteria): CC6.1, CC6.2, CC6.3, CC7.1
- ISO 27001 (Annex A): A.9.2.3, A.9.2.5, A.9.4.1, A.9.1.2

**Flow:**
1. Map findings -> compliance controls via mapping config
2. Render Jinja2 HTML template grouped by control
3. If PDF requested, pipe through `weasyprint`

**Templates:** SOC 2, ISO 27001, Executive summary (1-page with risk score + top findings)

**New files:**
- `src/accessaudit/core/compliance/mappings.py`
- `src/accessaudit/core/compliance/soc2.py`
- `src/accessaudit/core/compliance/iso27001.py`
- `src/accessaudit/core/templates/reports/`

**New dependency:** `weasyprint>=61.0`

---

## Dependency Summary

**New required:**
- `weasyprint>=61.0`

**New optional (azure extra):**
- `msal>=1.26.0`
- `azure-identity>=1.15.0`
- `azure-mgmt-authorization>=4.0.0`
- `msgraph-core>=1.0.0`

**New optional (gcp extra):**
- `google-cloud-iam>=2.14.0`
- `google-auth>=2.27.0`
- `google-cloud-resource-manager>=1.12.0`

**External binary:**
- OPA (Open Policy Agent) - required for Rego policy engine
