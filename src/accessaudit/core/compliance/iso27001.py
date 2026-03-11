"""ISO 27001 Annex A control mappings."""

from accessaudit.models.finding import FindingCategory

ISO27001_CONTROLS: dict[str, dict] = {
    "A.9.1.2": {
        "name": "Access to Networks and Network Services",
        "description": (
            "Users shall only be provided with access to the network and network "
            "services that they have been specifically authorized to use."
        ),
        "categories": [
            FindingCategory.EXCESSIVE_PERMISSIONS,
            FindingCategory.POLICY_VIOLATION,
            FindingCategory.OVERPRIVILEGED_ROLE,
        ],
    },
    "A.9.2.3": {
        "name": "Management of Privileged Access Rights",
        "description": (
            "The allocation and use of privileged access rights shall be "
            "restricted and controlled."
        ),
        "categories": [
            FindingCategory.OVERPRIVILEGED_ROLE,
            FindingCategory.EXCESSIVE_PERMISSIONS,
        ],
    },
    "A.9.2.5": {
        "name": "Review of User Access Rights",
        "description": ("Asset owners shall review users' access rights at regular intervals."),
        "categories": [
            FindingCategory.DORMANT_ACCOUNT,
            FindingCategory.UNUSED_CREDENTIALS,
        ],
    },
    "A.9.4.1": {
        "name": "Information Access Restriction",
        "description": (
            "Access to information and application system functions shall be "
            "restricted in accordance with the access control policy."
        ),
        "categories": [
            FindingCategory.MISSING_MFA,
            FindingCategory.WEAK_PASSWORD,
            FindingCategory.ANOMALY,
        ],
    },
}
