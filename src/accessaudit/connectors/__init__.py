"""IAM provider connectors."""

from accessaudit.connectors.aws import AWSConnector
from accessaudit.connectors.base import BaseConnector

try:
    from accessaudit.connectors.azure import AzureConnector
except ImportError:
    AzureConnector = None  # type: ignore[assignment, misc]

try:
    from accessaudit.connectors.gcp import GCPConnector
except ImportError:
    GCPConnector = None  # type: ignore[assignment, misc]

try:
    from accessaudit.connectors.sailpoint import SailPointConnector
except ImportError:
    SailPointConnector = None  # type: ignore[assignment, misc]

__all__ = [
    "BaseConnector",
    "AWSConnector",
    "AzureConnector",
    "GCPConnector",
    "SailPointConnector",
]
