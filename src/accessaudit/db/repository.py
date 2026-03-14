"""Repository layer for database operations."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from accessaudit.core.analyzer import AnalysisResult
from accessaudit.core.scanner import ScanResult
from accessaudit.db.models import AnalysisDB, ScanDB, UserDB
from accessaudit.models import Account, Finding, Permission, Policy


def _serialize_scan(scan: ScanResult) -> dict[str, Any]:
    """Serialize ScanResult to JSONB-compatible dict."""
    return {
        "accounts": [a.model_dump(mode="json") for a in scan.accounts],
        "permissions": {
            k: [p.model_dump(mode="json") for p in v] for k, v in scan.permissions.items()
        },
        "policies": [p.model_dump(mode="json") for p in scan.policies],
    }


def _deserialize_scan(scan_db: ScanDB) -> ScanResult:
    """Convert ScanDB row to ScanResult."""
    data = scan_db.scan_data or {}

    accounts = [Account(**a) for a in data.get("accounts", [])]
    permissions = {k: [Permission(**p) for p in v] for k, v in data.get("permissions", {}).items()}
    policies = [Policy(**p) for p in data.get("policies", [])]

    return ScanResult(
        scan_id=str(scan_db.id),
        provider=scan_db.provider,
        started_at=scan_db.started_at,
        completed_at=scan_db.completed_at,
        accounts=accounts,
        permissions=permissions,
        policies=policies,
        errors=scan_db.errors or [],
        status=scan_db.status,
    )


def _deserialize_analysis(analysis_db: AnalysisDB) -> AnalysisResult:
    """Convert AnalysisDB row to AnalysisResult."""
    findings_data = analysis_db.findings or []
    findings = [Finding(**f) for f in findings_data]

    return AnalysisResult(
        scan_id=str(analysis_db.scan_id),
        analyzed_at=analysis_db.analyzed_at,
        findings=findings,
        summary=analysis_db.summary or {},
    )


class ScanRepository:
    """CRUD operations for scans."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, scan: ScanResult, user_id: uuid.UUID | None = None) -> ScanDB:
        """Persist a ScanResult."""
        scan_db = ScanDB(
            id=uuid.UUID(scan.scan_id) if _is_uuid(scan.scan_id) else uuid.uuid4(),
            provider=scan.provider,
            status=scan.status,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            account_count=len(scan.accounts),
            permission_count=sum(len(p) for p in scan.permissions.values()),
            policy_count=len(scan.policies),
            errors=scan.errors if scan.errors else None,
            scan_data=_serialize_scan(scan),
            user_id=user_id,
        )
        self.session.add(scan_db)
        await self.session.flush()
        return scan_db

    async def get(self, scan_id: str) -> ScanResult | None:
        """Get a scan by ID."""
        try:
            uid = uuid.UUID(scan_id)
        except ValueError:
            return None
        row = await self.session.get(ScanDB, uid)
        if row is None:
            return None
        return _deserialize_scan(row)

    async def list_all(self) -> list[ScanResult]:
        """List all scans ordered by started_at desc."""
        result = await self.session.execute(select(ScanDB).order_by(ScanDB.started_at.desc()))
        return [_deserialize_scan(row) for row in result.scalars().all()]

    async def update_status(
        self, scan_id: str, status: str, completed_at: datetime | None = None
    ) -> None:
        """Update scan status."""
        try:
            uid = uuid.UUID(scan_id)
        except ValueError:
            return
        row = await self.session.get(ScanDB, uid)
        if row:
            row.status = status
            if completed_at:
                row.completed_at = completed_at
            await self.session.flush()

    async def update(self, scan: ScanResult) -> None:
        """Update full scan data."""
        try:
            uid = uuid.UUID(scan.scan_id)
        except ValueError:
            return
        row = await self.session.get(ScanDB, uid)
        if row:
            row.status = scan.status
            row.completed_at = scan.completed_at
            row.account_count = len(scan.accounts)
            row.permission_count = sum(len(p) for p in scan.permissions.values())
            row.policy_count = len(scan.policies)
            row.errors = scan.errors if scan.errors else None
            row.scan_data = _serialize_scan(scan)
            await self.session.flush()


class AnalysisRepository:
    """CRUD operations for analyses."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, analysis: AnalysisResult) -> AnalysisDB:
        """Persist an AnalysisResult."""
        analysis_db = AnalysisDB(
            scan_id=uuid.UUID(analysis.scan_id),
            analyzed_at=analysis.analyzed_at,
            finding_count=len(analysis.findings),
            findings=[f.to_dict() for f in analysis.findings],
            summary=analysis.summary,
        )
        self.session.add(analysis_db)
        await self.session.flush()
        return analysis_db

    async def get_by_scan_id(self, scan_id: str) -> AnalysisResult | None:
        """Get analysis by scan ID."""
        try:
            uid = uuid.UUID(scan_id)
        except ValueError:
            return None
        result = await self.session.execute(select(AnalysisDB).where(AnalysisDB.scan_id == uid))
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _deserialize_analysis(row)


class UserRepository:
    """CRUD operations for users."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, email: str, password_hash: str, api_key: str) -> UserDB:
        """Create a new user."""
        user = UserDB(email=email, password_hash=password_hash, api_key=api_key)
        self.session.add(user)
        await self.session.flush()
        return user

    async def get_by_email(self, email: str) -> UserDB | None:
        """Get user by email."""
        result = await self.session.execute(select(UserDB).where(UserDB.email == email))
        return result.scalar_one_or_none()

    async def get_by_api_key(self, api_key: str) -> UserDB | None:
        """Get user by API key."""
        result = await self.session.execute(select(UserDB).where(UserDB.api_key == api_key))
        return result.scalar_one_or_none()

    async def get_by_id(self, user_id: uuid.UUID) -> UserDB | None:
        """Get user by ID."""
        return await self.session.get(UserDB, user_id)

    async def update_api_key(self, user_id: uuid.UUID, new_api_key: str) -> None:
        """Rotate user's API key."""
        user = await self.session.get(UserDB, user_id)
        if user:
            user.api_key = new_api_key
            await self.session.flush()


def _is_uuid(value: str) -> bool:
    """Check if a string is a valid UUID."""
    try:
        uuid.UUID(value)
        return True
    except ValueError:
        return False
