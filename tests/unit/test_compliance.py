"""Tests for SOC 2 and ISO 27001 compliance mappings."""

import pytest

from accessaudit.models.finding import Finding, FindingCategory, FindingSeverity


class TestSOC2Controls:
    """Tests for SOC 2 control mappings."""

    def test_soc2_controls_exist(self):
        from accessaudit.core.compliance.soc2 import SOC2_CONTROLS

        assert isinstance(SOC2_CONTROLS, dict)
        assert len(SOC2_CONTROLS) >= 4

    def test_soc2_has_required_control_ids(self):
        from accessaudit.core.compliance.soc2 import SOC2_CONTROLS

        for control_id in ["CC6.1", "CC6.2", "CC6.3", "CC7.1"]:
            assert control_id in SOC2_CONTROLS, f"Missing control {control_id}"

    def test_soc2_control_structure(self):
        from accessaudit.core.compliance.soc2 import SOC2_CONTROLS

        for control_id, control in SOC2_CONTROLS.items():
            assert "name" in control, f"{control_id} missing 'name'"
            assert "description" in control, f"{control_id} missing 'description'"
            assert "categories" in control, f"{control_id} missing 'categories'"
            assert isinstance(control["categories"], list)
            for cat in control["categories"]:
                assert isinstance(cat, FindingCategory)

    def test_soc2_cc6_1_maps_to_access_controls(self):
        from accessaudit.core.compliance.soc2 import SOC2_CONTROLS

        categories = SOC2_CONTROLS["CC6.1"]["categories"]
        assert FindingCategory.EXCESSIVE_PERMISSIONS in categories

    def test_soc2_cc6_2_maps_to_credentials(self):
        from accessaudit.core.compliance.soc2 import SOC2_CONTROLS

        categories = SOC2_CONTROLS["CC6.2"]["categories"]
        assert FindingCategory.WEAK_PASSWORD in categories or FindingCategory.MISSING_MFA in categories

    def test_soc2_cc7_1_maps_to_monitoring(self):
        from accessaudit.core.compliance.soc2 import SOC2_CONTROLS

        categories = SOC2_CONTROLS["CC7.1"]["categories"]
        assert FindingCategory.ANOMALY in categories or FindingCategory.DORMANT_ACCOUNT in categories


class TestISO27001Controls:
    """Tests for ISO 27001 control mappings."""

    def test_iso27001_controls_exist(self):
        from accessaudit.core.compliance.iso27001 import ISO27001_CONTROLS

        assert isinstance(ISO27001_CONTROLS, dict)
        assert len(ISO27001_CONTROLS) >= 4

    def test_iso27001_has_required_control_ids(self):
        from accessaudit.core.compliance.iso27001 import ISO27001_CONTROLS

        for control_id in ["A.9.2.3", "A.9.2.5", "A.9.4.1", "A.9.1.2"]:
            assert control_id in ISO27001_CONTROLS, f"Missing control {control_id}"

    def test_iso27001_control_structure(self):
        from accessaudit.core.compliance.iso27001 import ISO27001_CONTROLS

        for control_id, control in ISO27001_CONTROLS.items():
            assert "name" in control, f"{control_id} missing 'name'"
            assert "description" in control, f"{control_id} missing 'description'"
            assert "categories" in control, f"{control_id} missing 'categories'"
            assert isinstance(control["categories"], list)
            for cat in control["categories"]:
                assert isinstance(cat, FindingCategory)

    def test_iso27001_a923_maps_to_privileged_access(self):
        from accessaudit.core.compliance.iso27001 import ISO27001_CONTROLS

        categories = ISO27001_CONTROLS["A.9.2.3"]["categories"]
        assert FindingCategory.OVERPRIVILEGED_ROLE in categories or FindingCategory.EXCESSIVE_PERMISSIONS in categories

    def test_iso27001_a925_maps_to_access_review(self):
        from accessaudit.core.compliance.iso27001 import ISO27001_CONTROLS

        categories = ISO27001_CONTROLS["A.9.2.5"]["categories"]
        assert FindingCategory.DORMANT_ACCOUNT in categories or FindingCategory.UNUSED_CREDENTIALS in categories


class TestComplianceMapper:
    """Tests for the ComplianceMapper class."""

    def _make_finding(self, category: FindingCategory, severity: FindingSeverity = FindingSeverity.HIGH) -> Finding:
        return Finding(
            id="test-001",
            severity=severity,
            category=category,
            account_id="arn:aws:iam::123456789012:user/test",
            title=f"Test finding: {category.value}",
            description="Test description",
            remediation="Test remediation",
        )

    def test_mapper_soc2_returns_controls(self):
        from accessaudit.core.compliance.mappings import ComplianceMapper

        mapper = ComplianceMapper()
        findings = [self._make_finding(FindingCategory.EXCESSIVE_PERMISSIONS)]
        result = mapper.map_findings("soc2", findings)

        assert isinstance(result, list)
        assert len(result) > 0

    def test_mapper_soc2_control_structure(self):
        from accessaudit.core.compliance.mappings import ComplianceMapper

        mapper = ComplianceMapper()
        findings = [self._make_finding(FindingCategory.EXCESSIVE_PERMISSIONS)]
        result = mapper.map_findings("soc2", findings)

        for item in result:
            assert "control_id" in item
            assert "control_name" in item
            assert "findings" in item
            assert "status" in item
            assert item["status"] in ("pass", "fail")

    def test_mapper_soc2_fail_when_findings_match(self):
        from accessaudit.core.compliance.mappings import ComplianceMapper

        mapper = ComplianceMapper()
        findings = [self._make_finding(FindingCategory.EXCESSIVE_PERMISSIONS)]
        result = mapper.map_findings("soc2", findings)

        # CC6.1 should fail because it maps to EXCESSIVE_PERMISSIONS
        cc6_1 = next(r for r in result if r["control_id"] == "CC6.1")
        assert cc6_1["status"] == "fail"
        assert len(cc6_1["findings"]) > 0

    def test_mapper_soc2_pass_when_no_findings(self):
        from accessaudit.core.compliance.mappings import ComplianceMapper

        mapper = ComplianceMapper()
        result = mapper.map_findings("soc2", [])

        for item in result:
            assert item["status"] == "pass"
            assert len(item["findings"]) == 0

    def test_mapper_iso27001_returns_controls(self):
        from accessaudit.core.compliance.mappings import ComplianceMapper

        mapper = ComplianceMapper()
        findings = [self._make_finding(FindingCategory.OVERPRIVILEGED_ROLE)]
        result = mapper.map_findings("iso27001", findings)

        assert isinstance(result, list)
        assert len(result) > 0

    def test_mapper_iso27001_fail_when_findings_match(self):
        from accessaudit.core.compliance.mappings import ComplianceMapper

        mapper = ComplianceMapper()
        findings = [self._make_finding(FindingCategory.OVERPRIVILEGED_ROLE)]
        result = mapper.map_findings("iso27001", findings)

        # A.9.2.3 should fail for overprivileged roles
        a923 = next(r for r in result if r["control_id"] == "A.9.2.3")
        assert a923["status"] == "fail"
        assert len(a923["findings"]) > 0

    def test_mapper_unknown_framework_raises(self):
        from accessaudit.core.compliance.mappings import ComplianceMapper

        mapper = ComplianceMapper()
        with pytest.raises(ValueError, match="Unknown.*framework"):
            mapper.map_findings("unknown_framework", [])

    def test_mapper_multiple_findings_multiple_controls(self):
        from accessaudit.core.compliance.mappings import ComplianceMapper

        mapper = ComplianceMapper()
        findings = [
            self._make_finding(FindingCategory.EXCESSIVE_PERMISSIONS),
            self._make_finding(FindingCategory.MISSING_MFA),
            self._make_finding(FindingCategory.DORMANT_ACCOUNT),
            self._make_finding(FindingCategory.ANOMALY),
        ]
        result = mapper.map_findings("soc2", findings)

        # Multiple controls should have findings
        controls_with_findings = [r for r in result if r["status"] == "fail"]
        assert len(controls_with_findings) >= 2
