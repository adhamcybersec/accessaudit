"""Mock GCP IAM data for testing."""


def make_gcp_service_account(
    email: str = "my-sa@project.iam.gserviceaccount.com",
    unique_id: str = "sa-001",
    display_name: str = "My Service Account",
    disabled: bool = False,
) -> dict:
    return {
        "name": f"projects/my-project/serviceAccounts/{email}",
        "email": email,
        "uniqueId": unique_id,
        "displayName": display_name,
        "disabled": disabled,
    }


def make_gcp_iam_binding(
    role: str = "roles/editor",
    members: list[str] | None = None,
) -> dict:
    return {
        "role": role,
        "members": members or ["serviceAccount:my-sa@project.iam.gserviceaccount.com"],
    }


def make_gcp_role(
    name: str = "roles/editor",
    title: str = "Editor",
    permissions: list[str] | None = None,
    stage: str = "GA",
) -> dict:
    return {
        "name": name,
        "title": title,
        "includedPermissions": permissions or ["resourcemanager.projects.get"],
        "stage": stage,
    }
