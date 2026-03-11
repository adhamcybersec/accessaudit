"""Unit tests for connectors (mocked)."""

from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from accessaudit.connectors.aws import AWSConnector
from accessaudit.connectors.base import BaseConnector
from accessaudit.models import AccountStatus


class TestBaseConnector:
    """Tests for BaseConnector ABC."""

    @pytest.mark.asyncio
    async def test_list_roles_returns_empty_list_by_default(self):
        """Test that list_roles() returns empty list by default."""
        connector = AWSConnector({"region": "us-east-1"})
        roles = await connector.list_roles()
        assert roles == []


class TestAWSConnector:
    """Tests for AWSConnector with mocked boto3."""

    @pytest.fixture
    def mock_boto3_client(self):
        """Create mock boto3 IAM client."""
        mock_client = MagicMock()

        # Mock list_users response
        mock_client.get_paginator.return_value.paginate.return_value = [
            {
                "Users": [
                    {
                        "UserName": "test-user",
                        "UserId": "AIDAEXAMPLE12345",
                        "Arn": "arn:aws:iam::123456789012:user/test-user",
                        "Path": "/",
                        "CreateDate": datetime(2023, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
                    },
                    {
                        "UserName": "admin-user",
                        "UserId": "AIDAEXAMPLE67890",
                        "Arn": "arn:aws:iam::123456789012:user/admin-user",
                        "Path": "/",
                        "CreateDate": datetime(2022, 6, 1, 8, 0, 0, tzinfo=timezone.utc),
                    },
                ]
            }
        ]

        # Mock other IAM methods
        mock_client.list_access_keys.return_value = {"AccessKeyMetadata": []}
        mock_client.list_mfa_devices.return_value = {"MFADevices": []}
        mock_client.list_groups_for_user.return_value = {"Groups": []}
        mock_client.list_user_tags.return_value = {"Tags": []}
        mock_client.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        mock_client.list_user_policies.return_value = {"PolicyNames": []}
        mock_client.list_policies.return_value = {"Policies": []}

        return mock_client

    @pytest.fixture
    def connector(self):
        """Create connector instance."""
        return AWSConnector({"region": "us-east-1"})

    @pytest.mark.asyncio
    async def test_list_accounts(self, connector, mock_boto3_client):
        """Test listing IAM accounts."""
        with patch("boto3.client", return_value=mock_boto3_client):
            connector.iam_client = mock_boto3_client

            accounts = await connector.list_accounts()

            assert len(accounts) == 2
            assert accounts[0].username == "test-user"
            assert accounts[0].provider == "aws"
            assert accounts[1].username == "admin-user"

    @pytest.mark.asyncio
    async def test_get_account_permissions(self, connector, mock_boto3_client):
        """Test getting account permissions."""
        # Set up mock for attached policies
        mock_boto3_client.list_attached_user_policies.return_value = {
            "AttachedPolicies": [
                {
                    "PolicyName": "AmazonS3ReadOnlyAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                }
            ]
        }

        # Mock get_policy
        mock_boto3_client.get_policy.return_value = {
            "Policy": {
                "PolicyName": "AmazonS3ReadOnlyAccess",
                "Arn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                "DefaultVersionId": "v1",
            }
        }

        # Mock get_policy_version
        mock_boto3_client.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:Get*", "s3:List*"],
                            "Resource": "*",
                        }
                    ],
                }
            }
        }

        with patch("boto3.client", return_value=mock_boto3_client):
            connector.iam_client = mock_boto3_client

            permissions = await connector.get_account_permissions("test-user")

            assert len(permissions) >= 1
            assert permissions[0].resource_type in ["s3", "unknown"]

    @pytest.mark.asyncio
    async def test_test_connection_success(self, connector, mock_boto3_client):
        """Test successful connection test."""
        mock_boto3_client.get_user.return_value = {"User": {"UserName": "caller"}}

        with patch("boto3.client", return_value=mock_boto3_client):
            result = await connector.test_connection()
            assert result is True

    @pytest.mark.asyncio
    async def test_test_connection_failure(self, connector):
        """Test failed connection test."""
        from botocore.exceptions import NoCredentialsError

        mock_client = MagicMock()
        mock_client.get_user.side_effect = NoCredentialsError()
        mock_client.list_users.side_effect = NoCredentialsError()

        with patch("boto3.client", return_value=mock_client):
            result = await connector.test_connection()
            assert result is False

    def test_connector_initialization(self):
        """Test connector initialization."""
        connector = AWSConnector({
            "region": "eu-west-1",
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "secret",
        })

        assert connector.region == "eu-west-1"
        assert connector.config["access_key_id"] == "AKIAEXAMPLE"

    @pytest.mark.asyncio
    async def test_user_to_account_conversion(self, connector, mock_boto3_client):
        """Test AWS user to Account model conversion."""
        user = {
            "UserName": "test-user",
            "UserId": "AIDAEXAMPLE12345",
            "Arn": "arn:aws:iam::123456789012:user/test-user",
            "Path": "/",
            "CreateDate": datetime(2023, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
        }

        connector.iam_client = mock_boto3_client

        account = await connector._user_to_account(user)

        assert account.username == "test-user"
        assert account.id == "arn:aws:iam::123456789012:user/test-user"
        assert account.provider == "aws"
        assert account.status == AccountStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_admin_detection(self, connector, mock_boto3_client):
        """Test admin permission detection."""
        mock_boto3_client.list_attached_user_policies.return_value = {
            "AttachedPolicies": [
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                }
            ]
        }
        mock_boto3_client.list_groups_for_user.return_value = {"Groups": []}

        connector.iam_client = mock_boto3_client

        has_admin = await connector._check_admin_permissions("admin-user")

        assert has_admin is True

    @pytest.mark.asyncio
    async def test_non_admin_detection(self, connector, mock_boto3_client):
        """Test non-admin user detection."""
        mock_boto3_client.list_attached_user_policies.return_value = {
            "AttachedPolicies": [
                {
                    "PolicyName": "AmazonS3ReadOnlyAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
                }
            ]
        }
        mock_boto3_client.list_groups_for_user.return_value = {"Groups": []}

        connector.iam_client = mock_boto3_client

        has_admin = await connector._check_admin_permissions("regular-user")

        assert has_admin is False
