"""Unit tests for analysis modules."""

from datetime import datetime, timezone, timedelta

import pytest

from accessaudit.analysis.anomaly import AnomalyDetector
from accessaudit.analysis.dormant import DormantAccountAnalyzer
from accessaudit.analysis.permissions import PermissionAnalyzer
from accessaudit.analysis.rules import Rule, RuleEngine
from accessaudit.core.analyzer import Analyzer
from accessaudit.models import Account, AccountStatus, FindingCategory, FindingSeverity, Permission


class TestPermissionAnalyzer:
    """Tests for PermissionAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return PermissionAnalyzer({"max_permissions_threshold": 50})

    @pytest.fixture
    def admin_account(self):
        """Create admin account fixture."""
        return Account(
            id="arn:aws:iam::123456789012:user/admin",
            provider="aws",
            username="admin",
            has_admin_role=True,
            mfa_enabled=False,
        )

    @pytest.fixture
    def regular_account(self):
        """Create regular account fixture."""
        return Account(
            id="arn:aws:iam::123456789012:user/regular",
            provider="aws",
            username="regular",
            has_admin_role=False,
            mfa_enabled=True,
        )

    @pytest.mark.asyncio
    async def test_detect_wildcard_permissions(self, analyzer, admin_account):
        """Test detection of wildcard permissions."""
        permissions = [
            Permission(
                id="perm-1",
                account_id=admin_account.id,
                resource_type="all",
                resource_arn="*",
                actions=["*"],
                source_policy="arn:aws:iam::aws:policy/AdministratorAccess",
            )
        ]

        findings = await analyzer.analyze([admin_account], {admin_account.id: permissions})

        assert len(findings) >= 1
        wildcard_findings = [
            f for f in findings if f.category == FindingCategory.EXCESSIVE_PERMISSIONS
        ]
        assert len(wildcard_findings) >= 1
        assert wildcard_findings[0].severity == FindingSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_detect_admin_without_mfa(self, analyzer, admin_account):
        """Test detection of admin accounts without MFA."""
        permissions = [
            Permission(
                id="perm-1",
                account_id=admin_account.id,
                resource_type="iam",
                resource_arn="*",
                actions=["iam:*"],
                source_policy="policy-1",
            )
        ]

        findings = await analyzer.analyze([admin_account], {admin_account.id: permissions})

        mfa_findings = [f for f in findings if f.category == FindingCategory.MISSING_MFA]
        assert len(mfa_findings) == 1
        assert mfa_findings[0].severity == FindingSeverity.HIGH

    @pytest.mark.asyncio
    async def test_no_findings_for_limited_permissions(self, analyzer, regular_account):
        """Test no findings for limited permissions."""
        permissions = [
            Permission(
                id="perm-1",
                account_id=regular_account.id,
                resource_type="s3",
                resource_arn="arn:aws:s3:::my-bucket/*",
                actions=["s3:GetObject"],
                source_policy="policy-1",
            )
        ]

        findings = await analyzer.analyze([regular_account], {regular_account.id: permissions})

        # Should have no critical/high findings
        critical_high = [
            f for f in findings if f.severity in [FindingSeverity.CRITICAL, FindingSeverity.HIGH]
        ]
        assert len(critical_high) == 0

    @pytest.mark.asyncio
    async def test_detect_excessive_permissions(self, analyzer, regular_account):
        """Test detection of excessive number of permissions."""
        # Create many permissions
        permissions = [
            Permission(
                id=f"perm-{i}",
                account_id=regular_account.id,
                resource_type="s3",
                resource_arn=f"arn:aws:s3:::bucket-{i}/*",
                actions=["s3:GetObject"],
                source_policy="policy-1",
            )
            for i in range(60)  # Exceeds threshold of 50
        ]

        findings = await analyzer.analyze([regular_account], {regular_account.id: permissions})

        excessive_findings = [
            f for f in findings if "excessive" in f.title.lower()
        ]
        assert len(excessive_findings) == 1


class TestDormantAccountAnalyzer:
    """Tests for DormantAccountAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return DormantAccountAnalyzer({"dormant_threshold_days": 90})

    @pytest.mark.asyncio
    async def test_detect_dormant_account(self, analyzer):
        """Test detection of dormant accounts."""
        dormant_account = Account(
            id="user-1",
            provider="aws",
            username="dormant-user",
            last_activity=datetime.now(timezone.utc) - timedelta(days=200),  # > 180 days = MEDIUM
        )

        findings = await analyzer.analyze([dormant_account])

        assert len(findings) == 1
        assert findings[0].category == FindingCategory.DORMANT_ACCOUNT
        assert findings[0].severity == FindingSeverity.MEDIUM

    @pytest.mark.asyncio
    async def test_no_finding_for_active_account(self, analyzer):
        """Test no finding for active accounts."""
        active_account = Account(
            id="user-1",
            provider="aws",
            username="active-user",
            last_activity=datetime.now(timezone.utc) - timedelta(days=30),
        )

        findings = await analyzer.analyze([active_account])

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_severity_based_on_inactivity(self, analyzer):
        """Test severity increases with inactivity duration."""
        very_dormant = Account(
            id="user-1",
            provider="aws",
            username="very-dormant",
            last_activity=datetime.now(timezone.utc) - timedelta(days=400),
        )

        findings = await analyzer.analyze([very_dormant])

        assert len(findings) == 1
        assert findings[0].severity == FindingSeverity.HIGH


class TestRuleEngine:
    """Tests for RuleEngine."""

    @pytest.fixture
    def rule_engine(self):
        """Create rule engine with test rules."""
        rules = [
            {
                "name": "Admin without MFA",
                "severity": "high",
                "condition": "account.has_admin_role AND NOT account.mfa_enabled",
                "description": "Admin accounts must have MFA",
                "remediation": "Enable MFA",
            }
        ]
        return RuleEngine(rules)

    @pytest.mark.asyncio
    async def test_rule_evaluation(self, rule_engine):
        """Test rule evaluation against accounts."""
        admin_no_mfa = Account(
            id="user-1",
            provider="aws",
            username="admin",
            has_admin_role=True,
            mfa_enabled=False,
        )

        findings = await rule_engine.analyze([admin_no_mfa], {admin_no_mfa.id: []})

        assert len(findings) >= 1
        assert any(f.category == FindingCategory.POLICY_VIOLATION for f in findings)

    @pytest.mark.asyncio
    async def test_rule_not_triggered(self, rule_engine):
        """Test rule not triggered when conditions not met."""
        admin_with_mfa = Account(
            id="user-1",
            provider="aws",
            username="admin",
            has_admin_role=True,
            mfa_enabled=True,
        )

        findings = await rule_engine.analyze([admin_with_mfa], {admin_with_mfa.id: []})

        # Should not trigger the "Admin without MFA" rule
        admin_mfa_findings = [
            f for f in findings if "admin" in f.title.lower() and "mfa" in f.title.lower()
        ]
        assert len(admin_mfa_findings) == 0


class TestRule:
    """Tests for individual Rule class."""

    def test_rule_creation(self):
        """Test rule creation."""
        rule = Rule(
            name="Test Rule",
            severity="high",
            condition="account.has_admin_role",
            description="Test description",
            remediation="Test remediation",
        )
        assert rule.name == "Test Rule"
        assert rule.severity == FindingSeverity.HIGH

    def test_rule_evaluation_simple(self):
        """Test simple rule evaluation."""
        rule = Rule(
            name="Admin Check",
            severity="high",
            condition="account.has_admin_role",
        )

        admin_account = Account(
            id="user-1",
            provider="aws",
            username="admin",
            has_admin_role=True,
        )

        result = rule.evaluate({"account": admin_account})
        assert result is True

        regular_account = Account(
            id="user-2",
            provider="aws",
            username="regular",
            has_admin_role=False,
        )

        result = rule.evaluate({"account": regular_account})
        assert result is False


class TestAnalyzerAnomalyIntegration:
    """Tests for AnomalyDetector integration in Analyzer."""

    def test_analyzer_has_anomaly_detector(self):
        """Analyzer should have an anomaly_detector attribute."""
        analyzer = Analyzer()
        assert hasattr(analyzer, "anomaly_detector")
        assert isinstance(analyzer.anomaly_detector, AnomalyDetector)
