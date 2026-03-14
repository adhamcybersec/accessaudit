# AccessAudit — Cloud IAM Auditing Tool

## Inheritance
**Parent**: `~/CLAUDE.md`
**Inherits**: Core identity (Theo), operating principles, git rules (no AI attribution), permissions

---

## Project Overview

**AccessAudit** — Open-source cloud IAM auditing tool for multi-provider security compliance.
**Owner**: Adham (adhamcybersec)
**GitHub**: `adhamcybersec/accessaudit`
**Status**: Phase 2 complete (18 tasks, CI green as of 2026-03-12)

## Architecture

- **Source**: `src/accessaudit/` (setuptools with package-dir)
- **Models**: Pydantic v2 with StrEnum enums
- **API**: FastAPI with in-memory stores (`app.state.scans`, `app.state.analyses`)
- **Background scans**: `asyncio.create_task()` with task reference retention
- **Templates**: Jinja2 + Tailwind CSS CDN + HTMX CDN
- **Reports**: HTML/PDF compliance reports (WeasyPrint)
- **CLI**: Typer with `scan/analyze/report/serve` commands

## Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.12+ |
| API | FastAPI |
| Cloud Connectors | AWS (boto3/LocalStack), Azure AD, GCP |
| ML | scikit-learn (anomaly detection) |
| Policy | OPA/Rego (SOC2, ISO 27001, CIS AWS rule packs) |
| Dashboard | HTMX + Jinja2 + Tailwind |
| CLI | Typer |

## CI Pipeline

- **Lint**: Black (v26+, pinned), Ruff, mypy (strict + pydantic plugin)
- **Test**: pytest with coverage
- **Build**: setuptools package + twine check
- **Docker**: docker/build-push-action
- **Integration**: LocalStack v3 service container with Docker health checks

### CI Lessons Learned
- Pin Black version explicitly (v26+ changed formatting)
- LocalStack needs Docker health checks before tests run
- mypy strict mode requires `types-PyYAML` and pydantic plugin
- Migrated from isort to Ruff for import sorting

## Conventions

- **Testing**: pytest
- **Formatting**: Black + Ruff
- **Commits**: Conventional commits (feat:, fix:, refactor:, docs:)
- **Type checking**: mypy strict mode

## Quick Commands

```bash
cd /phoenix/projects/accessaudit

# Lint
black --check src/ tests/ && ruff check src/ tests/ && mypy src/

# Test
pytest tests/ -v --cov=accessaudit

# Run API
python -m accessaudit serve

# CLI
python -m accessaudit scan --provider aws
python -m accessaudit analyze --scan-id <id>
python -m accessaudit report --format pdf
```
