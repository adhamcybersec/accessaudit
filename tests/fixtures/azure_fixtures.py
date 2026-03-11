"""Mock Azure AD and RBAC data for testing."""


def make_azure_user(
    user_id: str = "user-001",
    display_name: str = "John Doe",
    upn: str = "john.doe@contoso.com",
    account_enabled: bool = True,
    mfa_registered: bool = True,
    member_of: list[str] | None = None,
    last_sign_in: str | None = "2026-03-01T10:00:00Z",
) -> dict:
    """Create a mock Azure AD user."""
    return {
        "id": user_id,
        "displayName": display_name,
        "userPrincipalName": upn,
        "accountEnabled": account_enabled,
        "createdDateTime": "2025-01-15T10:00:00Z",
        "signInActivity": {
            "lastSignInDateTime": last_sign_in,
        } if last_sign_in else None,
        "memberOf": [{"displayName": g} for g in (member_of or [])],
    }


def make_azure_directory_role(
    role_id: str = "role-001",
    display_name: str = "Global Administrator",
    members: list[str] | None = None,
) -> dict:
    """Create a mock Azure directory role."""
    return {
        "id": role_id,
        "displayName": display_name,
        "members": members or [],
    }


def make_azure_rbac_assignment(
    assignment_id: str = "assign-001",
    principal_id: str = "user-001",
    role_definition_name: str = "Contributor",
    scope: str = "/subscriptions/sub-001",
) -> dict:
    """Create a mock Azure RBAC role assignment."""
    return {
        "id": assignment_id,
        "properties": {
            "principalId": principal_id,
            "roleDefinitionId": f"/providers/Microsoft.Authorization/roleDefinitions/{assignment_id}",
            "scope": scope,
        },
        "role_definition_name": role_definition_name,
    }


def make_azure_service_principal(
    sp_id: str = "sp-001",
    display_name: str = "MyApp",
    app_id: str = "app-001",
) -> dict:
    """Create a mock Azure service principal."""
    return {
        "id": sp_id,
        "displayName": display_name,
        "appId": app_id,
        "servicePrincipalType": "Application",
    }
