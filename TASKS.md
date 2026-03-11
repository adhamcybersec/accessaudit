# AccessAudit - Implementation Tasks

## Phase 1: MVP (Core AWS IAM Support)

### Project Setup
- [x] Create project structure
- [x] Set up pyproject.toml
- [x] Write README.md
- [ ] Create .gitignore
- [ ] Set up virtual environment
- [ ] Install dependencies
- [ ] Initialize Git repository

### Core Models
- [ ] `src/accessaudit/models/__init__.py` - Model exports
- [ ] `src/accessaudit/models/account.py` - Account data model
- [ ] `src/accessaudit/models/permission.py` - Permission model
- [ ] `src/accessaudit/models/policy.py` - Policy model
- [ ] `src/accessaudit/models/finding.py` - Finding/issue model

### Connector Layer
- [ ] `src/accessaudit/connectors/__init__.py` - Connector registry
- [ ] `src/accessaudit/connectors/base.py` - Base connector interface (ABC)
- [ ] `src/accessaudit/connectors/aws.py` - AWS IAM connector (boto3)
  - [ ] List users, roles, groups
  - [ ] Fetch attached policies
  - [ ] Get inline policies
  - [ ] Parse policy documents
  - [ ] Get last access timestamps

### Analysis Engine
- [ ] `src/accessaudit/analysis/__init__.py`
- [ ] `src/accessaudit/analysis/permissions.py` - Permission analyzer
  - [ ] Detect wildcard (`*`) policies
  - [ ] Flag admin-level permissions
  - [ ] Calculate permission scope (read/write/admin)
- [ ] `src/accessaudit/analysis/dormant.py` - Dormant account detection
  - [ ] Check last login timestamps
  - [ ] Flag accounts inactive >90 days
- [ ] `src/accessaudit/analysis/rules.py` - Policy rule engine
  - [ ] Load rules from YAML config
  - [ ] Evaluate rules against policies
  - [ ] Generate findings

### Core Services
- [ ] `src/accessaudit/core/__init__.py`
- [ ] `src/accessaudit/core/scanner.py` - Scan orchestrator
  - [ ] Coordinate connector execution
  - [ ] Aggregate results
  - [ ] Trigger analysis
- [ ] `src/accessaudit/core/analyzer.py` - Analysis orchestrator
  - [ ] Run all analyzers
  - [ ] Collect findings
  - [ ] Calculate risk scores
- [ ] `src/accessaudit/core/reporter.py` - Report generator
  - [ ] Generate JSON reports
  - [ ] Summary statistics
  - [ ] Remediation recommendations

### CLI Tool
- [ ] `src/accessaudit/cli/__init__.py`
- [ ] `src/accessaudit/cli/main.py` - CLI entrypoint (Typer)
  - [ ] `scan` command - Trigger scans
  - [ ] `findings` command - List findings
  - [ ] `report` command - Generate reports
  - [ ] `config` command - Manage configuration

### Configuration
- [ ] `src/accessaudit/utils/__init__.py`
- [ ] `src/accessaudit/utils/config.py` - Config management
  - [ ] Load from YAML
  - [ ] Environment variable overrides
  - [ ] Validation
- [ ] `src/accessaudit/utils/logging.py` - Logging setup
  - [ ] Structured logging (JSON)
  - [ ] Log levels (DEBUG, INFO, WARNING, ERROR)

### Testing
- [ ] `tests/unit/test_models.py` - Model tests
- [ ] `tests/unit/test_connectors.py` - Connector tests (mocked)
- [ ] `tests/unit/test_analysis.py` - Analysis tests
- [ ] `tests/integration/test_aws_scan.py` - End-to-end AWS scan test
- [ ] `tests/fixtures/` - Mock IAM data

### Docker
- [ ] `docker/Dockerfile` - Production container
- [ ] `docker/docker-compose.yml` - Development stack (PostgreSQL, Redis)
- [ ] `.dockerignore`

### Documentation
- [ ] `docs/getting-started.md` - Installation & setup
- [ ] `docs/aws-connector.md` - AWS IAM connector docs
- [ ] `docs/configuration.md` - Config reference
- [ ] `LICENSE` - MIT license file

### CI/CD
- [ ] `.github/workflows/ci.yml` - GitHub Actions
  - [ ] Run tests
  - [ ] Linting (black, ruff)
  - [ ] Type checking (mypy)

---

## Implementation Order (Suggested)

1. **Models first** - Define data structures
2. **Base connector** - Abstract interface
3. **AWS connector** - Concrete implementation
4. **Analysis modules** - Detection logic
5. **Core services** - Orchestration
6. **CLI tool** - User interface
7. **Tests** - Unit + integration
8. **Docker** - Packaging
9. **Documentation** - Usage guides

---

## Testing Strategy

- **Unit tests:** Mock external APIs (boto3), test logic
- **Integration tests:** Use LocalStack or real AWS sandbox account
- **Manual testing:** Run against real AWS account with test users

---

## Definition of Done (MVP)

- [ ] Can scan AWS IAM users, roles, policies
- [ ] Detects excessive permissions (wildcards)
- [ ] Detects dormant accounts (>90 days)
- [ ] Generates JSON report with findings
- [ ] CLI tool works end-to-end
- [ ] Unit tests >80% coverage
- [ ] Docker image builds successfully
- [ ] README with usage examples
- [ ] Tagged v0.1.0 release

---

**Estimated Effort:** ~2-3 days for MVP (with Claude Code)  
**Developer:** Claude Code  
**Architect/PM:** Davis
