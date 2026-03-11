"""ML anomaly detection for IAM accounts using Isolation Forest."""

import uuid

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from accessaudit.analysis.features import FeatureExtractor
from accessaudit.models import Account, Finding, FindingSeverity, Permission
from accessaudit.models.finding import FindingCategory


class AnomalyDetector:
    """Detects anomalous IAM accounts using Isolation Forest per peer group.

    Groups accounts by shared group membership (peers), extracts feature
    vectors, normalises them, and runs sklearn IsolationForest to flag
    outliers.
    """

    def __init__(
        self,
        min_group_size: int = 10,
        contamination: float = 0.1,
    ) -> None:
        """Initialise anomaly detector.

        Args:
            min_group_size: Minimum peer-group size to run detection on.
                Groups smaller than this are skipped (too few samples).
            contamination: Expected proportion of outliers in the data
                (passed to IsolationForest).
        """
        self.min_group_size = min_group_size
        self.contamination = contamination
        self._feature_extractor = FeatureExtractor()

    def detect(
        self,
        accounts: list[Account],
        permissions: dict[str, list[Permission]],
    ) -> list[Finding]:
        """Run anomaly detection across all peer groups.

        Args:
            accounts: All accounts to analyse.
            permissions: Mapping of account_id -> list of Permission objects.

        Returns:
            List of Finding objects for detected anomalies.
        """
        findings: list[Finding] = []

        # Group accounts by peer membership
        peer_groups = self._feature_extractor.group_by_peers(accounts)

        for group_name, group_accounts in peer_groups.items():
            if len(group_accounts) < self.min_group_size:
                continue

            group_findings = self._detect_in_group(group_name, group_accounts, permissions)
            findings.extend(group_findings)

        return findings

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _detect_in_group(
        self,
        group_name: str,
        accounts: list[Account],
        permissions: dict[str, list[Permission]],
    ) -> list[Finding]:
        """Run Isolation Forest on a single peer group.

        Args:
            group_name: Name of the peer group.
            accounts: Accounts in this group.
            permissions: Full permissions mapping.

        Returns:
            Findings for outlier accounts in this group.
        """
        # Extract feature vectors
        vectors, account_ids = self._feature_extractor.extract(accounts, permissions)

        if not vectors or len(vectors) < 2:
            return []

        # Normalise features
        features_array = np.array(vectors, dtype=np.float64)
        scaler = StandardScaler()
        features_scaled = scaler.fit_transform(features_array)

        # Run Isolation Forest
        model = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
        )
        predictions = model.fit_predict(features_scaled)
        scores = model.decision_function(features_scaled)

        # Build findings for outliers (prediction == -1)
        findings: list[Finding] = []
        for idx, (pred, score) in enumerate(zip(predictions, scores, strict=False)):
            if pred == -1:
                account_id = account_ids[idx]
                severity = self._score_to_severity(score)
                finding = Finding(
                    id=f"anomaly-{uuid.uuid4().hex[:8]}",
                    severity=severity,
                    category=FindingCategory.ANOMALY,
                    account_id=account_id,
                    title=f"Anomalous access pattern in group '{group_name}'",
                    description=(
                        f"Account {account_id} has an unusual permission profile "
                        f"compared to peers in group '{group_name}'. "
                        f"Anomaly score: {score:.4f}."
                    ),
                    remediation=(
                        "Review this account's permissions and compare with "
                        "peer accounts in the same group. Remove any unnecessary "
                        "or excessive permissions."
                    ),
                    metadata={
                        "anomaly_score": float(score),
                        "peer_group": group_name,
                        "group_size": len(accounts),
                    },
                )
                findings.append(finding)

        return findings

    @staticmethod
    def _score_to_severity(score: float) -> FindingSeverity:
        """Map anomaly score to finding severity.

        Lower (more negative) scores indicate stronger anomalies.

        Args:
            score: Anomaly score from IsolationForest.decision_function().

        Returns:
            FindingSeverity based on score thresholds.
        """
        if score < -0.5:
            return FindingSeverity.HIGH
        if score < -0.3:
            return FindingSeverity.MEDIUM
        return FindingSeverity.LOW
