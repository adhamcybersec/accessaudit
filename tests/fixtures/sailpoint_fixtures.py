"""Mock SailPoint IIQ SCIM API responses."""

SERVICE_PROVIDER_CONFIG = {
    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
    "documentationUri": "https://docs.sailpoint.com",
    "patch": {"supported": True},
    "bulk": {"supported": False},
    "filter": {"supported": True, "maxResults": 200},
    "changePassword": {"supported": True},
    "sort": {"supported": True},
    "etag": {"supported": False},
    "authenticationSchemes": [
        {
            "type": "httpbasic",
            "name": "HTTP Basic",
            "description": "Authentication via HTTP Basic",
        }
    ],
}

SCIM_USERS_RESPONSE = {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    "totalResults": 2,
    "startIndex": 1,
    "itemsPerPage": 100,
    "Resources": [
        {
            "id": "user-001",
            "userName": "john.doe",
            "displayName": "John Doe",
            "name": {"givenName": "John", "familyName": "Doe"},
            "active": True,
            "emails": [{"value": "john.doe@example.com", "primary": True}],
            "groups": [
                {"value": "grp-001", "display": "IT Administrators", "$ref": "/scim/v2/Groups/grp-001"}
            ],
            "meta": {
                "resourceType": "User",
                "created": "2024-01-15T10:00:00Z",
                "lastModified": "2025-12-01T14:30:00Z",
            },
        },
        {
            "id": "user-002",
            "userName": "jane.smith",
            "displayName": "Jane Smith",
            "name": {"givenName": "Jane", "familyName": "Smith"},
            "active": True,
            "emails": [{"value": "jane.smith@example.com", "primary": True}],
            "groups": [
                {"value": "grp-002", "display": "Read Only Users", "$ref": "/scim/v2/Groups/grp-002"}
            ],
            "meta": {
                "resourceType": "User",
                "created": "2024-06-01T08:00:00Z",
                "lastModified": "2026-01-15T09:00:00Z",
            },
        },
    ],
}

SCIM_ROLES_RESPONSE = {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    "totalResults": 1,
    "startIndex": 1,
    "itemsPerPage": 100,
    "Resources": [
        {
            "id": "role-001",
            "displayName": "IT Administrator",
            "members": [{"value": "user-001"}],
            "meta": {
                "resourceType": "Role",
                "created": "2023-01-01T00:00:00Z",
                "lastModified": "2025-06-01T00:00:00Z",
            },
        }
    ],
}

SCIM_ENTITLEMENTS_RESPONSE = {
    "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
    "totalResults": 1,
    "startIndex": 1,
    "itemsPerPage": 100,
    "Resources": [
        {
            "id": "ent-001",
            "displayName": "Full Admin Access",
            "name": "AdminAccess",
            "type": "admin",
            "application": "ActiveDirectory",
            "meta": {"resourceType": "Entitlement"},
        }
    ],
}

SCIM_USER_DETAIL = SCIM_USERS_RESPONSE["Resources"][0]
