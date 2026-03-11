package accessaudit.iso27001

# A.9.1.2 - Access to Networks and Services: Broad network-related permissions
violation[result] {
    some perm in input.permissions
    perm.effect == "Allow"
    perm.resource_type == "network"
    perm.resource_arn == "*"
    result := {
        "title": "A.9.1.2 - Unrestricted network access permissions",
        "severity": "high",
        "category": "network_access_control",
        "description": sprintf("Account has unrestricted network permissions via actions: %v", [perm.actions]),
        "remediation": "Restrict network permissions to specific VPCs, subnets, or security groups. Apply least-privilege principles to network access.",
    }
}

# A.9.1.2 - Access to Networks and Services: VPC or security group modification permissions
violation[result] {
    some perm in input.permissions
    perm.effect == "Allow"
    some action in perm.actions
    contains(action, "SecurityGroup")
    perm.resource_arn == "*"
    result := {
        "title": "A.9.1.2 - Broad security group modification access",
        "severity": "high",
        "category": "network_access_control",
        "description": sprintf("Account can modify security groups across all resources via action '%s'", [action]),
        "remediation": "Scope security group modification permissions to specific resources and require change management approval.",
    }
}

# A.9.2.3 - Management of Privileged Access Rights: Admin without MFA
violation[result] {
    account := input.account
    account.has_admin_role
    not account.mfa_enabled
    result := {
        "title": "A.9.2.3 - Privileged account without MFA",
        "severity": "critical",
        "category": "privileged_access_management",
        "description": sprintf("Admin account '%s' does not have multi-factor authentication enabled", [account.username]),
        "remediation": "Enable MFA immediately for all privileged accounts. ISO 27001 A.9.2.3 requires strong authentication for administrative access.",
    }
}

# A.9.2.3 - Management of Privileged Access Rights: Multiple admin policies
violation[result] {
    account := input.account
    account.has_admin_role
    count(input.policies) > 5
    result := {
        "title": "A.9.2.3 - Excessive policies on privileged account",
        "severity": "medium",
        "category": "privileged_access_management",
        "description": sprintf("Admin account '%s' has %d policies attached, indicating potential privilege accumulation", [account.username, count(input.policies)]),
        "remediation": "Consolidate policies and review whether all attached permissions are required. Follow the principle of least privilege.",
    }
}

# A.9.2.5 - Review of User Access Rights: Account not reviewed recently
violation[result] {
    account := input.account
    account.days_since_last_review > 90
    result := {
        "title": "A.9.2.5 - Access rights not reviewed within 90 days",
        "severity": "medium",
        "category": "access_review",
        "description": sprintf("Account '%s' has not had an access review in %d days", [account.username, account.days_since_last_review]),
        "remediation": "Conduct an access review for this account. ISO 27001 requires periodic review of user access rights.",
    }
}

# A.9.2.5 - Review of User Access Rights: Privileged account not reviewed recently
violation[result] {
    account := input.account
    account.has_admin_role
    account.days_since_last_review > 30
    result := {
        "title": "A.9.2.5 - Privileged access rights not reviewed within 30 days",
        "severity": "high",
        "category": "access_review",
        "description": sprintf("Admin account '%s' has not had an access review in %d days", [account.username, account.days_since_last_review]),
        "remediation": "Privileged accounts require more frequent access reviews. Conduct a review immediately and establish a 30-day review cycle.",
    }
}

# A.9.4.1 - Information Access Restriction: Broad resource access
violation[result] {
    some perm in input.permissions
    perm.effect == "Allow"
    perm.resource_arn == "*"
    count(perm.actions) > 10
    result := {
        "title": "A.9.4.1 - Excessive actions on unrestricted resources",
        "severity": "high",
        "category": "information_access_restriction",
        "description": sprintf("Permission grants %d actions on all resources (*), violating information access restrictions", [count(perm.actions)]),
        "remediation": "Restrict both the resource scope and action set. Each permission should target specific resources with minimal required actions.",
    }
}

# A.9.4.1 - Information Access Restriction: Wildcard actions on sensitive resource types
violation[result] {
    some perm in input.permissions
    perm.effect == "Allow"
    perm.actions[_] == "*"
    sensitive_types := {"database", "storage", "secrets", "kms"}
    sensitive_types[perm.resource_type]
    result := {
        "title": "A.9.4.1 - Wildcard access to sensitive resource type",
        "severity": "critical",
        "category": "information_access_restriction",
        "description": sprintf("Wildcard (*) actions granted on sensitive resource type '%s' (ARN: %s)", [perm.resource_type, perm.resource_arn]),
        "remediation": "Replace wildcard access with specific read/write permissions on sensitive resources. Apply data classification controls.",
    }
}
