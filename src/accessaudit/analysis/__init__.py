"""Analysis modules for IAM auditing."""

from accessaudit.analysis.anomaly import AnomalyDetector
from accessaudit.analysis.dormant import DormantAccountAnalyzer
from accessaudit.analysis.features import FeatureExtractor
from accessaudit.analysis.permissions import PermissionAnalyzer
from accessaudit.analysis.rules import RuleEngine

__all__ = [
    "AnomalyDetector",
    "DormantAccountAnalyzer",
    "FeatureExtractor",
    "PermissionAnalyzer",
    "RuleEngine",
]
