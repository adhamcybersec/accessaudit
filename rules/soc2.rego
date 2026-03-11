package accessaudit.soc2

# CC6.1 - Logical Access Security: Overly permissive wildcard actions
violation[result] {
    some perm in input.permissions
    perm.effect == "Allow"
    perm.actions[_] == "*"
    result := {
        "title": "CC6.1 - Wildcard actions in permission policy",
        "severity": "critical",
        "category": "logical_access_security",
        "description": sprintf("Permission on resource '%s' grants wildcard (*) actions", [perm.resource_arn]),
        "remediation": "Replace wildcard actions with specific, least-privilege permissions required for the role.",
    }
}

# CC6.1 - Logical Access Security: Overly permissive resource scope
violation[result] {
    some perm in input.permissions
    perm.effect == "Allow"
    perm.resource_arn == "*"
    result := {
        "title": "CC6.1 - Unrestricted resource scope in permission",
        "severity": "high",
        "category": "logical_access_security",
        "description": sprintf("Permission grants access to all resources (*) for actions: %v", [perm.actions]),
        "remediation": "Scope the resource ARN to the specific resources required rather than using a wildcard.",
    }
}

# CC6.1 - Logical Access Security: Inline policies on IAM users
violation[result] {
    some policy in input.policies
    policy.policy_type == "inline"
    result := {
        "title": "CC6.1 - Inline policy attached directly",
        "severity": "medium",
        "category": "logical_access_security",
        "description": sprintf("Inline policy '%s' is attached directly instead of through a managed policy", [policy.name]),
        "remediation": "Convert inline policies to managed policies for consistent access control and easier auditing.",
    }
}

# CC6.2 - Access Provisioning: Unused credentials (no activity and account older than 30 days)
violation[result] {
    account := input.account
    account.days_since_activity > 30
    account.days_since_created > 30
    not account.has_admin_role
    result := {
        "title": "CC6.2 - Unused credentials detected",
        "severity": "medium",
        "category": "access_provisioning",
        "description": sprintf("Account '%s' has been inactive for %d days and may have unused credentials", [account.username, account.days_since_activity]),
        "remediation": "Review whether the account is still needed. Disable or remove unused credentials.",
    }
}

# CC6.2 - Access Provisioning: Dormant admin accounts
violation[result] {
    account := input.account
    account.has_admin_role
    account.days_since_activity > 14
    result := {
        "title": "CC6.2 - Dormant privileged account",
        "severity": "high",
        "category": "access_provisioning",
        "description": sprintf("Admin account '%s' has been inactive for %d days", [account.username, account.days_since_activity]),
        "remediation": "Investigate dormant admin accounts immediately. Disable if no longer required.",
    }
}

# CC6.3 - Access Removal: Inactive accounts exceeding threshold
violation[result] {
    account := input.account
    account.days_since_activity > 90
    result := {
        "title": "CC6.3 - Inactive account exceeds 90-day threshold",
        "severity": "high",
        "category": "access_removal",
        "description": sprintf("Account '%s' has been inactive for %d days, exceeding the 90-day access removal threshold", [account.username, account.days_since_activity]),
        "remediation": "Disable or remove the account. SOC 2 requires timely deprovisioning of inactive accounts.",
    }
}

# CC6.3 - Access Removal: Account with no recorded last activity
violation[result] {
    account := input.account
    account.last_activity == ""
    account.days_since_created > 7
    result := {
        "title": "CC6.3 - Account with no recorded activity",
        "severity": "medium",
        "category": "access_removal",
        "description": sprintf("Account '%s' was created %d days ago but has no recorded activity", [account.username, account.days_since_created]),
        "remediation": "Verify the account is needed. Remove accounts that were provisioned but never used.",
    }
}

# CC7.1 - Monitoring and Detection: Accounts without audit logging
violation[result] {
    account := input.account
    not account.audit_logging_enabled
    result := {
        "title": "CC7.1 - Audit logging not enabled for account",
        "severity": "high",
        "category": "monitoring_detection",
        "description": sprintf("Account '%s' does not have audit logging enabled", [account.username]),
        "remediation": "Enable CloudTrail or equivalent audit logging for all accounts to meet SOC 2 monitoring requirements.",
    }
}

# CC7.1 - Monitoring and Detection: Admin accounts without audit logging
violation[result] {
    account := input.account
    account.has_admin_role
    not account.audit_logging_enabled
    result := {
        "title": "CC7.1 - Privileged account lacks audit logging",
        "severity": "critical",
        "category": "monitoring_detection",
        "description": sprintf("Admin account '%s' does not have audit logging enabled", [account.username]),
        "remediation": "Immediately enable comprehensive audit logging for all privileged accounts.",
    }
}
