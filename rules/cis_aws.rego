package accessaudit.cis_aws

# 1.1 - Avoid the use of the root account
violation[result] {
    account := input.account
    account.username == "root"
    account.days_since_activity < 30
    result := {
        "title": "CIS 1.1 - Root account recently used",
        "severity": "critical",
        "category": "identity_access_management",
        "description": sprintf("Root account was used within the last %d days", [account.days_since_activity]),
        "remediation": "Avoid using the root account for daily operations. Create individual IAM users with appropriate permissions instead.",
    }
}

# 1.1 - Root account should have MFA
violation[result] {
    account := input.account
    account.username == "root"
    not account.mfa_enabled
    result := {
        "title": "CIS 1.1 - Root account does not have MFA enabled",
        "severity": "critical",
        "category": "identity_access_management",
        "description": "The root account does not have multi-factor authentication enabled",
        "remediation": "Enable hardware MFA on the root account immediately. The root account has unrestricted access to all resources.",
    }
}

# 1.2 - MFA enabled for all IAM users with console access
violation[result] {
    account := input.account
    account.has_console_access
    not account.mfa_enabled
    result := {
        "title": "CIS 1.2 - Console user without MFA",
        "severity": "high",
        "category": "identity_access_management",
        "description": sprintf("IAM user '%s' has console access but MFA is not enabled", [account.username]),
        "remediation": "Enable MFA for all IAM users with AWS Management Console access. Consider enforcing MFA via IAM policy conditions.",
    }
}

# 1.3 - Credentials unused for 90 days should be disabled
violation[result] {
    account := input.account
    account.days_since_activity > 90
    result := {
        "title": "CIS 1.3 - Credentials unused for 90+ days",
        "severity": "high",
        "category": "identity_access_management",
        "description": sprintf("Account '%s' credentials have not been used for %d days", [account.username, account.days_since_activity]),
        "remediation": "Disable or remove credentials that have not been used in 90 days. Implement automated credential lifecycle management.",
    }
}

# 1.4 - Access keys rotated every 90 days
violation[result] {
    account := input.account
    account.days_since_key_rotation > 90
    result := {
        "title": "CIS 1.4 - Access key not rotated in 90+ days",
        "severity": "high",
        "category": "identity_access_management",
        "description": sprintf("Account '%s' has not rotated access keys in %d days", [account.username, account.days_since_key_rotation]),
        "remediation": "Rotate access keys at least every 90 days. Consider using IAM roles with temporary credentials instead of long-lived access keys.",
    }
}

# 1.4 - Access keys critically overdue for rotation
violation[result] {
    account := input.account
    account.days_since_key_rotation > 180
    result := {
        "title": "CIS 1.4 - Access key critically overdue for rotation",
        "severity": "critical",
        "category": "identity_access_management",
        "description": sprintf("Account '%s' has not rotated access keys in %d days (over 180 days)", [account.username, account.days_since_key_rotation]),
        "remediation": "Immediately rotate or deactivate access keys. Keys unused for over 180 days represent a significant security risk.",
    }
}

# 1.16 - No IAM policies attached directly to users
violation[result] {
    some policy in input.policies
    policy.attachment_type == "direct_user"
    result := {
        "title": "CIS 1.16 - IAM policy attached directly to user",
        "severity": "medium",
        "category": "identity_access_management",
        "description": sprintf("Policy '%s' is attached directly to the user instead of through a group or role", [policy.name]),
        "remediation": "Attach IAM policies to groups or roles, not directly to users. Assign users to appropriate groups for consistent access management.",
    }
}

# 1.16 - User not assigned to any groups (should use groups for permissions)
violation[result] {
    account := input.account
    count(account.groups) == 0
    count(input.policies) > 0
    result := {
        "title": "CIS 1.16 - User has policies but no group membership",
        "severity": "medium",
        "category": "identity_access_management",
        "description": sprintf("Account '%s' has %d policies but is not a member of any IAM groups", [account.username, count(input.policies)]),
        "remediation": "Create appropriate IAM groups with the required policies and add the user to those groups. Remove direct policy attachments.",
    }
}
