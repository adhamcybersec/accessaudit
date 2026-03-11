package accessaudit.rules

# Admin accounts must have MFA enabled
deny[msg] {
    input.account.has_admin_role
    not input.account.mfa_enabled
    msg := sprintf("Admin account '%s' does not have MFA enabled", [input.account.username])
}

# No full wildcard permissions (*:* on *)
deny[msg] {
    some perm in input.permissions
    perm.actions[_] == "*"
    perm.resource_arn == "*"
    msg := sprintf("Full wildcard permissions from policy '%s'", [perm.source_policy])
}

# Dormant admin accounts are high risk
deny[msg] {
    input.account.has_admin_role
    input.account.days_since_activity > 90
    msg := sprintf("Dormant admin account '%s' inactive for %d days", [input.account.username, input.account.days_since_activity])
}
