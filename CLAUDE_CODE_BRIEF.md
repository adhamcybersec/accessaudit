# Welcome, Claude Code!

Hi! I'm Davis, and I'll be your architect/PM for this project. You're the implementation specialist.

## Project: AccessAudit

**What we're building:** An IAM access review automation platform - think automated security audits for AWS IAM, Azure AD, GCP, and SailPoint.

**Your role:** Implement the MVP (Phase 1) - AWS IAM support with core analysis features.

## What's Already Done

✅ Project structure created  
✅ `pyproject.toml` - Dependencies defined  
✅ `README.md` - Project overview  
✅ `ARCHITECTURE.md` - Detailed system design  
✅ `PROJECT_BRIEF.md` - Vision & goals  
✅ `TASKS.md` - Implementation checklist  
✅ `.gitignore`, `LICENSE` - Boilerplate  

## Your Mission (MVP Phase 1)

Build a working AWS IAM scanner that:

1. **Connects to AWS IAM** (boto3)
   - Lists users, roles, groups
   - Fetches policies (managed + inline)
   - Gets last access timestamps

2. **Analyzes permissions**
   - Detects wildcard (`*`) policies (excessive permissions)
   - Flags dormant accounts (inactive >90 days)
   - Evaluates custom rules from config

3. **Generates reports**
   - JSON output with findings
   - Risk scoring
   - Remediation recommendations

4. **CLI interface** (Typer)
   - `accessaudit scan aws` - Trigger scan
   - `accessaudit findings list` - View results
   - `accessaudit report generate` - Export reports

5. **Testing**
   - Unit tests (>80% coverage)
   - Mock AWS responses
   - Integration test (optional: LocalStack or real AWS)

6. **Docker packaging**
   - Dockerfile for production
   - docker-compose.yml for dev stack

## Implementation Guidelines

- **Python 3.11+** with type hints
- **Follow ARCHITECTURE.md** - The design is solid, stick to it
- **Test as you go** - Don't leave testing until the end
- **Keep it simple** - MVP first, fancy stuff later
- **Use Pydantic** for data validation
- **Async where it matters** - I/O bound operations (boto3 calls)

## Key Files to Implement

See `TASKS.md` for the full checklist. Start with:

1. **Models** (`src/accessaudit/models/`) - Data structures
2. **Base Connector** (`src/accessaudit/connectors/base.py`) - Interface
3. **AWS Connector** (`src/accessaudit/connectors/aws.py`) - Implementation
4. **Analysis Modules** (`src/accessaudit/analysis/`) - Detection logic
5. **Core Services** (`src/accessaudit/core/`) - Orchestration
6. **CLI** (`src/accessaudit/cli/main.py`) - User interface

## Definition of Done (MVP)

✅ Can scan real AWS IAM accounts  
✅ Detects excessive permissions + dormant accounts  
✅ Generates JSON report  
✅ CLI works end-to-end  
✅ Unit tests pass (>80% coverage)  
✅ Docker image builds  
✅ README has usage examples  
✅ Ready for v0.1.0 release  

## Communication

- **Ask questions** if the architecture is unclear
- **Suggest improvements** if you see a better way
- **Keep me updated** on progress (when you hit milestones)
- **Flag blockers** immediately

## My Role

- Architecture & design decisions
- Code review
- Testing & debugging
- Documentation polish
- Release management

## Your Tools

- `/mnt/secure-data/openclaw-workspace/` - Shared workspace (if needed)
- Full AWS CLI/SDK access (use test credentials when needed)
- Internet access for documentation/research

---

**Let's build something great!** 🚀

Start by setting up the virtual environment and implementing the core models. Work through `TASKS.md` systematically.

- Davis
