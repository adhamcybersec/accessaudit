# AccessAudit - Implementation Tasks

## Phase 1: MVP (Core AWS IAM Support) ✅ COMPLETE

### Project Setup ✅
- [x] Create project structure
- [x] Set up pyproject.toml
- [x] Write README.md
- [x] Create .gitignore
- [x] Set up virtual environment
- [x] Install dependencies
- [x] Initialize Git repository

### Core Models ✅
- [x] `src/accessaudit/models/__init__.py` - Model exports
- [x] `src/accessaudit/models/account.py` - Account data model
- [x] `src/accessaudit/models/permission.py` - Permission model
- [x] `src/accessaudit/models/policy.py` - Policy model
- [x] `src/accessaudit/models/finding.py` - Finding/issue model

### Connector Layer ✅
- [x] `src/accessaudit/connectors/__init__.py` - Connector registry
- [x] `src/accessaudit/connectors/base.py` - Base connector interface (ABC)
- [x] `src/accessaudit/connectors/aws.py` - AWS IAM connector (boto3)
  - [x] List users, roles, groups
  - [x] Fetch attached policies
  - [x] Get inline policies
  - [x] Parse policy documents
  - [x] Get last access timestamps

### Analysis Engine ✅
- [x] `src/accessaudit/analysis/__init__.py`
- [x] `src/accessaudit/analysis/permissions.py` - Permission analyzer
  - [x] Detect wildcard (`*`) policies
  - [x] Flag admin-level permissions
  - [x] Calculate permission scope (read/write/admin)
- [x] `src/accessaudit/analysis/dormant.py` - Dormant account detection
  - [x] Check last login timestamps
  - [x] Flag accounts inactive >90 days
- [x] `src/accessaudit/analysis/rules.py` - Policy rule engine
  - [x] Load rules from YAML config
  - [x] Evaluate rules against policies
  - [x] Generate findings

### Core Services ✅
- [x] `src/accessaudit/core/__init__.py`
- [x] `src/accessaudit/core/scanner.py` - Scan orchestrator
  - [x] Coordinate connector execution
  - [x] Aggregate results
  - [x] Trigger analysis
- [x] `src/accessaudit/core/analyzer.py` - Analysis orchestrator
  - [x] Run all analyzers
  - [x] Collect findings
  - [x] Calculate risk scores
- [x] `src/accessaudit/core/reporter.py` - Report generator
  - [x] Generate JSON reports
  - [x] Summary statistics
  - [x] Remediation recommendations

### CLI Tool ✅
- [x] `src/accessaudit/cli/__init__.py`
- [x] `src/accessaudit/cli/main.py` - CLI entrypoint (Typer)
  - [x] `scan` command - Trigger scans
  - [x] `findings` command - List findings
  - [x] `report` command - Generate reports
  - [x] `config` command - Manage configuration

### Configuration ✅
- [x] `src/accessaudit/utils/__init__.py`
- [x] `src/accessaudit/utils/config.py` - Config management
  - [x] Load from YAML
  - [x] Environment variable overrides
  - [x] Validation
- [x] `src/accessaudit/utils/logging.py` - Logging setup
  - [x] Structured logging (JSON)
  - [x] Log levels (DEBUG, INFO, WARNING, ERROR)

### Testing ✅
- [x] `tests/unit/test_models.py` - Model tests (16 tests)
- [x] `tests/unit/test_connectors.py` - Connector tests (8 tests)
- [x] `tests/unit/test_analysis.py` - Analysis tests (11 tests)
- [x] `tests/integration/test_aws_scan.py` - End-to-end AWS scan test
- [x] `tests/fixtures/` - Mock IAM data
- **Total: 40 tests passing**

### Docker ✅
- [x] `docker/Dockerfile` - Production container
- [x] `docker/docker-compose.yml` - Development stack (PostgreSQL, Redis)
- [x] `.dockerignore` (via .gitignore)

### Documentation ✅
- [x] `docs/getting-started.md` - Installation & setup
- [x] `docs/aws-connector.md` - AWS IAM connector docs
- [x] `docs/configuration.md` - Config reference
- [x] `LICENSE` - MIT license file
- [x] `examples/config.example.yaml` - Example config

### CI/CD ✅
- [x] `.github/workflows/ci.yml` - GitHub Actions
  - [x] Run tests
  - [x] Linting (black, ruff)
  - [x] Type checking (mypy)
  - [x] Docker build

---

## MVP Definition of Done ✅

- [x] Can scan AWS IAM users, roles, policies
- [x] Detects excessive permissions (wildcards)
- [x] Detects dormant accounts (>90 days)
- [x] Generates JSON report with findings
- [x] CLI tool works end-to-end
- [x] Unit tests (40 tests passing)
- [x] Docker image builds successfully
- [x] README with usage examples
- [x] Ready for v0.1.0 release

---

## Phase 2: Multi-Provider + Dashboard ✅ COMPLETE

- [x] Azure AD connector
- [x] GCP IAM connector
- [x] ML-based anomaly detection (Isolation Forest)
- [x] Web dashboard (HTMX + Tailwind CSS)
- [x] Compliance report templates (SOC 2, ISO 27001, CIS AWS)
- [x] OPA/Rego policy engine with rule packs
- [x] API server (FastAPI)
- [x] HTML + PDF report generation
- [x] Integration tests for Phase 2 features

---

## Phase 2.5: Infrastructure Gaps ✅ COMPLETE

### Database Layer ✅
- [x] `src/accessaudit/db/engine.py` - AsyncEngine singleton, session factory
- [x] `src/accessaudit/db/models.py` - SQLAlchemy 2.0 models (UserDB, ScanDB, AnalysisDB)
- [x] `src/accessaudit/db/repository.py` - CRUD repositories with serialization
- [x] `alembic.ini` + async migration environment
- [x] Migration 001: users, scans, analyses tables

### Redis Cache ✅
- [x] `src/accessaudit/db/cache.py` - CacheService with graceful degradation
  - [x] Get/set/invalidate for scans and analyses
  - [x] 1-hour TTL, no-op when Redis unavailable

### Storage Abstraction ✅
- [x] `src/accessaudit/services/storage.py` - StorageBackend protocol
  - [x] InMemoryStorage (backward compatible)
  - [x] DatabaseStorage (repository + read-through cache)

### Authentication ✅
- [x] `src/accessaudit/auth/security.py` - bcrypt + JWT + API key utilities
- [x] `src/accessaudit/auth/dependencies.py` - FastAPI auth dependencies
- [x] `src/accessaudit/auth/routes.py` - Register, login, me, rotate-key
- [x] `src/accessaudit/auth/models.py` - Pydantic auth models

### Wiring ✅
- [x] Lifespan context manager (DB, Redis, storage init/teardown)
- [x] All routes migrated to StorageBackend
- [x] Health endpoint with component status
- [x] Config additions (DatabaseConfig, RedisConfig, AuthConfig)
- [x] Docker Compose env vars (DATABASE_URL, REDIS_URL, AUTH_SECRET_KEY)

### Infrastructure Tests ✅
- [x] `tests/unit/test_storage.py` - InMemoryStorage tests
- [x] `tests/unit/test_cache.py` - CacheService tests (with/without Redis)
- [x] `tests/unit/test_auth.py` - Security utilities tests
- [x] `tests/unit/test_auth_routes.py` - Auth endpoint tests

### CI Updates ✅
- [x] PostgreSQL + Redis service containers in CI
- [x] Alembic migration step before integration tests
- [x] `tests/integration/test_persistence.py` - Full persistence flow

---

## Phase 3: New Features ✅ COMPLETE

### SailPoint IIQ Connector ✅
- [x] `src/accessaudit/connectors/sailpoint.py` - SCIM 2.0 connector
  - [x] SCIM Users -> Account mapping
  - [x] Entitlements -> Permission mapping
  - [x] Roles -> Policy mapping
  - [x] HTTP Basic and OAuth2 Bearer auth
  - [x] Pagination support
- [x] Scanner and CLI integration (`scan sailpoint` command)
- [x] `tests/unit/test_sailpoint_connector.py` - 10 tests
- [x] `tests/fixtures/sailpoint_fixtures.py` - Mock SCIM responses

### Notification System ✅
- [x] `src/accessaudit/notifications/base.py` - NotificationEventType, Notification model, BaseProvider ABC
- [x] `src/accessaudit/notifications/manager.py` - NotificationManager (routing, severity filter, 3x retry)
- [x] `src/accessaudit/notifications/slack.py` - Slack Incoming Webhook (Block Kit)
- [x] `src/accessaudit/notifications/teams.py` - Teams Incoming Webhook (Adaptive Cards)
- [x] `src/accessaudit/notifications/webhook.py` - Generic webhook (HMAC signing)
- [x] `src/accessaudit/api/routes/notifications.py` - Config, test, history endpoints
- [x] `tests/unit/test_notifications.py` - 8 tests

### Scheduled Scans ✅
- [x] `src/accessaudit/scheduling/models.py` - ScheduledScan Pydantic + SQLAlchemy models
- [x] `src/accessaudit/scheduling/service.py` - SchedulerService (cron via croniter, asyncio tasks)
- [x] `src/accessaudit/api/routes/schedules.py` - CRUD + enable/disable/runs endpoints
- [x] Migration 002: scheduled_scans table
- [x] `tests/unit/test_scheduling.py` - 11 tests

### Remediation Automation ✅
- [x] `src/accessaudit/remediation/models.py` - State machine (PENDING -> APPROVED -> EXECUTING -> COMPLETED/FAILED)
  - [x] RemediationStatus, RemediationActionType StrEnums
  - [x] Valid transition map with enforcement
- [x] `src/accessaudit/remediation/engine.py` - RemediationEngine (execute, rollback, retry)
- [x] `src/accessaudit/remediation/suggestions.py` - Auto-generate actions from findings by category
- [x] `src/accessaudit/api/routes/remediation.py` - Approve, reject, execute, rollback, bulk-approve
- [x] `src/accessaudit/connectors/base.py` - Optional remediation methods on BaseConnector
- [x] Migration 003: remediation_actions table
- [x] `tests/unit/test_remediation.py` - 15 tests

### Dashboard Updates ✅
- [x] `src/accessaudit/api/templates/schedules.html` - Schedule management page
- [x] `src/accessaudit/api/templates/notifications.html` - Notification config + history page
- [x] `src/accessaudit/api/templates/remediation.html` - Remediation actions + status cards
- [x] Updated `base.html` navigation (Schedules, Notifications, Remediation)

### Integration Tests ✅
- [x] `tests/integration/test_scheduled_scan.py` - Schedule CRUD lifecycle
- [x] `tests/integration/test_remediation_workflow.py` - Suggest -> approve -> execute flow
- [x] `tests/integration/test_notification_delivery.py` - Notification test endpoint

### Final Stats
- **198 tests passing** (121 Phase 1-2 + 77 Phase 2.5-3)
- **Black, Ruff, mypy all clean**
- **All existing tests preserved** via in-memory fallback

---

## Phase 4: Roadmap (Planned)

### Multi-Account & Cross-Cloud
- [ ] Multi-account AWS scanning (Organizations API, assume-role)
- [ ] Cross-account access analysis (who can access what across accounts)
- [ ] Unified identity view across AWS + Azure + GCP + SailPoint
- [ ] Permission diff: compare two scans to detect drift

### SSO & Identity Federation
- [ ] SAML/OIDC SSO for dashboard login
- [ ] Okta connector (SCIM + Okta API)
- [ ] Auth0 connector
- [ ] Ping Identity connector

### Advanced Connectors
- [ ] Kubernetes RBAC connector (ClusterRole, RoleBinding scanning)
- [ ] GitHub/GitLab access connector (repo permissions, org roles)
- [ ] HashiCorp Vault connector (policy + token auditing)
- [ ] Snowflake IAM connector (role grants, warehouse access)

### Remediation Playbooks
- [ ] Composable action sequences (multi-step remediation)
- [ ] Playbook templates (e.g., "offboard user" = disable + revoke + rotate)
- [ ] Dry-run mode for remediation actions
- [ ] AWS connector remediation implementation (detach_policy, disable_login, etc.)
- [ ] Azure/GCP connector remediation methods

### Analytics & Trends
- [ ] Risk trend analysis over time (track risk score per scan)
- [ ] Permission growth tracking (detect scope creep)
- [ ] Compliance posture dashboard (trend charts)
- [ ] Finding SLA tracking (time-to-remediate metrics)

### Enterprise Features
- [ ] Multi-tenant support (org-level isolation)
- [ ] RBAC for dashboard (admin, auditor, viewer roles)
- [ ] Audit log for all API actions
- [ ] Rate limiting per API key
- [ ] Data retention policies (auto-purge old scans)

### Integrations
- [ ] SIEM integration (Splunk, Elastic, Sentinel)
- [ ] Terraform provider for policy-as-code deployment
- [ ] ServiceNow ITSM integration (auto-create tickets from findings)
- [ ] Jira integration (create issues from findings)
- [ ] PagerDuty integration (critical finding alerts)

### PyPI Package Distribution
- [ ] Finalize `pyproject.toml` metadata (description, classifiers, URLs, long_description)
- [ ] Add `py.typed` marker file for PEP 561 type-checking support
- [ ] Create `MANIFEST.in` to include templates, migrations, and rule files in sdist
- [ ] Verify `python -m build` produces valid wheel and sdist
- [ ] Set up Trusted Publisher on PyPI (GitHub Actions OIDC)
- [ ] Add `publish` job to CI: build -> twine check -> upload to PyPI on tag push
- [ ] Test installation: `pip install accessaudit` in clean venv
- [ ] Test extras: `pip install accessaudit[azure]`, `pip install accessaudit[gcp]`, `pip install accessaudit[all]`
- [ ] Verify CLI entry point works after pip install: `accessaudit --version`
- [ ] Verify `accessaudit serve` works after pip install (templates bundled)
- [ ] Add `CHANGELOG.md` with semantic versioning
- [ ] Tag v0.2.0 release on GitHub with release notes

### MCP Server (Model Context Protocol)
- [ ] `src/accessaudit/mcp/__init__.py` - MCP package init
- [ ] `src/accessaudit/mcp/server.py` - MCP server using `mcp` SDK
  - [ ] Tool: `scan` - Trigger an IAM scan (provider, config) -> scan_id + status
  - [ ] Tool: `get_scan` - Get scan result by ID -> scan summary
  - [ ] Tool: `analyze` - Run analysis on a scan -> finding count + top findings
  - [ ] Tool: `list_findings` - List findings with severity/category filters
  - [ ] Tool: `get_finding` - Get detailed finding info by ID
  - [ ] Tool: `generate_report` - Generate compliance report (json/html)
  - [ ] Tool: `list_schedules` - List scheduled scans
  - [ ] Tool: `create_schedule` - Create a cron-based scheduled scan
  - [ ] Tool: `list_remediations` - List remediation actions
  - [ ] Tool: `suggest_remediations` - Generate remediation suggestions for a scan
  - [ ] Tool: `approve_remediation` - Approve a pending remediation action
  - [ ] Tool: `health` - Check service health and component status
  - [ ] Resource: `accessaudit://scans` - List of all scans as MCP resource
  - [ ] Resource: `accessaudit://findings/{scan_id}` - Findings for a scan
  - [ ] Resource: `accessaudit://config` - Current configuration summary
- [ ] `src/accessaudit/mcp/tools.py` - Tool definitions with JSON Schema input/output
- [ ] `src/accessaudit/mcp/resources.py` - MCP resource providers
- [ ] Add `mcp>=1.0.0` to dependencies
- [ ] CLI entry point: `accessaudit mcp` command to start MCP server (stdio transport)
- [ ] `pyproject.toml` script entry: `accessaudit-mcp = "accessaudit.mcp.server:main"`
- [ ] MCP config example for Claude Desktop / Claude Code (`claude_desktop_config.json`)
- [ ] `tests/unit/test_mcp_server.py` - Tool invocation tests
- [ ] Documentation: how to connect AccessAudit MCP to Claude Desktop / Claude Code

### Performance & Scale
- [ ] Async bulk scanning (scan 100+ accounts concurrently)
- [ ] Scan result diffing (only re-scan changed resources)
- [ ] Database partitioning for large scan histories
- [ ] Redis cluster support
- [ ] Horizontal scaling with shared scheduler (Redis-backed)

---

**Phase 1 Completed:** 2026-03-11
**Phase 2 Completed:** 2026-03-12
**Phase 2.5 Completed:** 2026-03-14
**Phase 3 Completed:** 2026-03-14
**Maintainer:** Adham Rashed ([@adhamcybersec](https://github.com/adhampx))
