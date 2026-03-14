"""Storage abstraction with in-memory and database backends."""

from __future__ import annotations

import logging
from typing import Any, Protocol, runtime_checkable

from accessaudit.core.analyzer import AnalysisResult
from accessaudit.core.scanner import ScanResult

logger = logging.getLogger(__name__)


@runtime_checkable
class StorageBackend(Protocol):
    """Protocol defining the storage interface."""

    async def save_scan(self, scan: ScanResult, user_id: str | None = None) -> None: ...

    async def get_scan(self, scan_id: str) -> ScanResult | None: ...

    async def list_scans(self) -> list[ScanResult]: ...

    async def update_scan(self, scan: ScanResult) -> None: ...

    async def save_analysis(self, analysis: AnalysisResult) -> None: ...

    async def get_analysis(self, scan_id: str) -> AnalysisResult | None: ...


class InMemoryStorage:
    """In-memory storage wrapping the existing dict pattern."""

    def __init__(self) -> None:
        self.scans: dict[str, ScanResult] = {}
        self.analyses: dict[str, AnalysisResult] = {}

    async def save_scan(self, scan: ScanResult, user_id: str | None = None) -> None:
        self.scans[scan.scan_id] = scan

    async def get_scan(self, scan_id: str) -> ScanResult | None:
        return self.scans.get(scan_id)

    async def list_scans(self) -> list[ScanResult]:
        return list(self.scans.values())

    async def update_scan(self, scan: ScanResult) -> None:
        self.scans[scan.scan_id] = scan

    async def save_analysis(self, analysis: AnalysisResult) -> None:
        self.analyses[analysis.scan_id] = analysis

    async def get_analysis(self, scan_id: str) -> AnalysisResult | None:
        return self.analyses.get(scan_id)


class DatabaseStorage:
    """Database + cache storage backend."""

    def __init__(self, session_factory: Any, cache: Any = None) -> None:
        self._session_factory = session_factory
        self._cache = cache

    async def save_scan(self, scan: ScanResult, user_id: str | None = None) -> None:
        import uuid

        from accessaudit.db.repository import ScanRepository

        async with self._session_factory() as session:
            repo = ScanRepository(session)
            uid = uuid.UUID(user_id) if user_id else None
            await repo.create(scan, user_id=uid)
            await session.commit()

        if self._cache:
            await self._cache.set_scan(scan.scan_id, scan.to_dict())

    async def get_scan(self, scan_id: str) -> ScanResult | None:
        # Try cache first
        if self._cache:
            cached = await self._cache.get_scan(scan_id)
            if cached is not None:
                return self._scan_from_cache(cached)

        from accessaudit.db.repository import ScanRepository

        async with self._session_factory() as session:
            repo = ScanRepository(session)
            scan = await repo.get(scan_id)

        if scan and self._cache:
            await self._cache.set_scan(scan_id, scan.to_dict())

        return scan

    async def list_scans(self) -> list[ScanResult]:
        from accessaudit.db.repository import ScanRepository

        async with self._session_factory() as session:
            repo = ScanRepository(session)
            return await repo.list_all()

    async def update_scan(self, scan: ScanResult) -> None:
        from accessaudit.db.repository import ScanRepository

        async with self._session_factory() as session:
            repo = ScanRepository(session)
            await repo.update(scan)
            await session.commit()

        if self._cache:
            await self._cache.invalidate_scan(scan.scan_id)
            await self._cache.set_scan(scan.scan_id, scan.to_dict())

    async def save_analysis(self, analysis: AnalysisResult) -> None:
        from accessaudit.db.repository import AnalysisRepository

        async with self._session_factory() as session:
            repo = AnalysisRepository(session)
            await repo.create(analysis)
            await session.commit()

        if self._cache:
            await self._cache.set_analysis(analysis.scan_id, analysis.to_dict())

    async def get_analysis(self, scan_id: str) -> AnalysisResult | None:
        if self._cache:
            cached = await self._cache.get_analysis(scan_id)
            if cached is not None:
                return self._analysis_from_cache(cached)

        from accessaudit.db.repository import AnalysisRepository

        async with self._session_factory() as session:
            repo = AnalysisRepository(session)
            analysis = await repo.get_by_scan_id(scan_id)

        if analysis and self._cache:
            await self._cache.set_analysis(scan_id, analysis.to_dict())

        return analysis

    def _scan_from_cache(self, data: dict[str, Any]) -> ScanResult:
        """Reconstruct a ScanResult from cached dict (summary only)."""
        from datetime import datetime

        return ScanResult(
            scan_id=data["scan_id"],
            provider=data["provider"],
            started_at=datetime.fromisoformat(data["started_at"]),
            completed_at=(
                datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None
            ),
            status=data["status"],
        )

    def _analysis_from_cache(self, data: dict[str, Any]) -> AnalysisResult:
        """Reconstruct an AnalysisResult from cached dict."""
        from datetime import datetime

        from accessaudit.models import Finding

        findings = [Finding(**f) for f in data.get("findings", [])]
        return AnalysisResult(
            scan_id=data["scan_id"],
            analyzed_at=datetime.fromisoformat(data["analyzed_at"]),
            findings=findings,
            summary=data.get("summary", {}),
        )
