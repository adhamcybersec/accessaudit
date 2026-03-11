"""IAM provider connectors."""

from accessaudit.connectors.base import BaseConnector
from accessaudit.connectors.aws import AWSConnector

try:
    from accessaudit.connectors.azure import AzureConnector
except ImportError:
    AzureConnector = None

try:
    from accessaudit.connectors.gcp import GCPConnector
except ImportError:
    GCPConnector = None

__all__ = ["BaseConnector", "AWSConnector", "AzureConnector", "GCPConnector"]
