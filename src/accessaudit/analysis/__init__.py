"""Analysis modules for IAM auditing."""

from accessaudit.analysis.dormant import DormantAccountAnalyzer
from accessaudit.analysis.features import FeatureExtractor
from accessaudit.analysis.permissions import PermissionAnalyzer
from accessaudit.analysis.rules import RuleEngine

__all__ = ["DormantAccountAnalyzer", "FeatureExtractor", "PermissionAnalyzer", "RuleEngine"]
