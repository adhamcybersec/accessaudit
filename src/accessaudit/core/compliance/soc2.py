"""SOC 2 Trust Services Criteria control mappings."""

from accessaudit.models.finding import FindingCategory

SOC2_CONTROLS: dict[str, dict] = {
    "CC6.1": {
        "name": "Logical and Physical Access Controls",
        "description": (
            "The entity implements logical access security software, infrastructure, "
            "and architectures over protected information assets to protect them from "
            "security events to meet the entity's objectives."
        ),
        "categories": [
            FindingCategory.EXCESSIVE_PERMISSIONS,
            FindingCategory.OVERPRIVILEGED_ROLE,
            FindingCategory.POLICY_VIOLATION,
        ],
    },
    "CC6.2": {
        "name": "User Authentication and Credential Management",
        "description": (
            "Prior to issuing system credentials and granting system access, the entity "
            "registers and authorizes new internal and external users whose access is "
            "administered by the entity."
        ),
        "categories": [
            FindingCategory.WEAK_PASSWORD,
            FindingCategory.MISSING_MFA,
            FindingCategory.UNUSED_CREDENTIALS,
        ],
    },
    "CC6.3": {
        "name": "Access Authorization and Modification",
        "description": (
            "The entity authorizes, modifies, or removes access to data, software, "
            "functions, and other protected information assets based on roles, "
            "responsibilities, or the system design and changes."
        ),
        "categories": [
            FindingCategory.EXCESSIVE_PERMISSIONS,
            FindingCategory.DORMANT_ACCOUNT,
            FindingCategory.UNUSED_CREDENTIALS,
        ],
    },
    "CC7.1": {
        "name": "System Monitoring and Anomaly Detection",
        "description": (
            "To meet its objectives, the entity uses detection and monitoring procedures "
            "to identify changes to configurations that result in the introduction of new "
            "vulnerabilities, and susceptibilities to newly discovered vulnerabilities."
        ),
        "categories": [
            FindingCategory.ANOMALY,
            FindingCategory.DORMANT_ACCOUNT,
        ],
    },
}
