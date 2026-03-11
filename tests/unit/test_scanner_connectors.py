"""Unit tests for scanner connector registration."""

import pytest

from accessaudit.core.scanner import Scanner
from accessaudit.connectors.aws import AWSConnector
from accessaudit.connectors.azure import AzureConnector
from accessaudit.connectors.gcp import GCPConnector


class TestScannerCreateConnector:
    """Tests for Scanner._create_connector with all providers."""

    @pytest.fixture
    def scanner(self):
        return Scanner()

    def test_create_aws_connector(self, scanner):
        """Scanner._create_connector('aws', ...) returns AWSConnector."""
        connector = scanner._create_connector("aws", {"region": "us-east-1"})
        assert isinstance(connector, AWSConnector)

    def test_create_azure_connector(self, scanner):
        """Scanner._create_connector('azure', ...) returns AzureConnector."""
        connector = scanner._create_connector("azure", {"tenant_id": "test"})
        assert isinstance(connector, AzureConnector)

    def test_create_gcp_connector(self, scanner):
        """Scanner._create_connector('gcp', ...) returns GCPConnector."""
        connector = scanner._create_connector("gcp", {"project_id": "test"})
        assert isinstance(connector, GCPConnector)

    def test_create_unsupported_connector(self, scanner):
        """Scanner._create_connector raises ValueError for unsupported providers."""
        with pytest.raises(ValueError, match="Unsupported provider"):
            scanner._create_connector("unsupported", {})
