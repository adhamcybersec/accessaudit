"""Tests for storage abstraction."""

from datetime import datetime

import pytest

from accessaudit.core.analyzer import AnalysisResult
from accessaudit.core.scanner import ScanResult
from accessaudit.services.storage import InMemoryStorage


@pytest.fixture
def storage():
    return InMemoryStorage()


@pytest.fixture
def sample_scan():
    return ScanResult(
        scan_id="test-scan-001",
        provider="aws",
        started_at=datetime.now(),
        status="completed",
    )


@pytest.fixture
def sample_analysis():
    return AnalysisResult(
        scan_id="test-scan-001",
        analyzed_at=datetime.now(),
        findings=[],
        summary={"total_findings": 0},
    )


async def test_save_and_get_scan(storage, sample_scan):
    await storage.save_scan(sample_scan)
    result = await storage.get_scan("test-scan-001")
    assert result is not None
    assert result.scan_id == "test-scan-001"
    assert result.provider == "aws"


async def test_get_nonexistent_scan(storage):
    result = await storage.get_scan("nonexistent")
    assert result is None


async def test_list_scans(storage, sample_scan):
    await storage.save_scan(sample_scan)
    scans = await storage.list_scans()
    assert len(scans) == 1
    assert scans[0].scan_id == "test-scan-001"


async def test_update_scan(storage, sample_scan):
    await storage.save_scan(sample_scan)
    sample_scan.status = "failed"
    await storage.update_scan(sample_scan)
    result = await storage.get_scan("test-scan-001")
    assert result is not None
    assert result.status == "failed"


async def test_save_and_get_analysis(storage, sample_analysis):
    await storage.save_analysis(sample_analysis)
    result = await storage.get_analysis("test-scan-001")
    assert result is not None
    assert result.scan_id == "test-scan-001"


async def test_get_nonexistent_analysis(storage):
    result = await storage.get_analysis("nonexistent")
    assert result is None


async def test_storage_implements_protocol():
    """Verify InMemoryStorage satisfies StorageBackend protocol."""
    from accessaudit.services.storage import StorageBackend

    assert isinstance(InMemoryStorage(), StorageBackend)
