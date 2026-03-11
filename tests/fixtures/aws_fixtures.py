"""AWS IAM test fixtures."""

from datetime import UTC, datetime, timedelta

# Mock AWS IAM users
MOCK_USERS = [
    {
        "UserName": "admin-user",
        "UserId": "AIDAEXAMPLE11111",
        "Arn": "arn:aws:iam::123456789012:user/admin-user",
        "Path": "/",
        "CreateDate": datetime(2023, 1, 15, 10, 30, 0, tzinfo=UTC),
    },
    {
        "UserName": "regular-user",
        "UserId": "AIDAEXAMPLE22222",
        "Arn": "arn:aws:iam::123456789012:user/regular-user",
        "Path": "/",
        "CreateDate": datetime(2023, 6, 1, 14, 0, 0, tzinfo=UTC),
    },
    {
        "UserName": "dormant-user",
        "UserId": "AIDAEXAMPLE33333",
        "Arn": "arn:aws:iam::123456789012:user/dormant-user",
        "Path": "/",
        "CreateDate": datetime(2022, 1, 1, 9, 0, 0, tzinfo=UTC),
    },
    {
        "UserName": "service-account",
        "UserId": "AIDAEXAMPLE44444",
        "Arn": "arn:aws:iam::123456789012:user/service-account",
        "Path": "/service-accounts/",
        "CreateDate": datetime(2024, 1, 1, 8, 0, 0, tzinfo=UTC),
    },
]

# Mock attached policies
MOCK_ATTACHED_POLICIES = {
    "admin-user": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
        }
    ],
    "regular-user": [
        {
            "PolicyName": "AmazonS3ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
        },
        {
            "PolicyName": "AmazonEC2ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess",
        },
    ],
    "dormant-user": [
        {
            "PolicyName": "AmazonS3FullAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3FullAccess",
        }
    ],
    "service-account": [
        {
            "PolicyName": "CustomServicePolicy",
            "PolicyArn": "arn:aws:iam::123456789012:policy/CustomServicePolicy",
        }
    ],
}

# Mock policy documents
MOCK_POLICY_DOCUMENTS = {
    "arn:aws:iam::aws:policy/AdministratorAccess": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    },
    "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:Get*",
                    "s3:List*",
                ],
                "Resource": "*",
            }
        ],
    },
    "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:Describe*",
                    "ec2:List*",
                ],
                "Resource": "*",
            }
        ],
    },
    "arn:aws:iam::aws:policy/AmazonS3FullAccess": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": "*",
            }
        ],
    },
    "arn:aws:iam::123456789012:policy/CustomServicePolicy": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:GetItem",
                    "dynamodb:PutItem",
                    "dynamodb:Query",
                ],
                "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable",
            }
        ],
    },
}

# Mock MFA devices
MOCK_MFA_DEVICES = {
    "admin-user": [],  # Admin without MFA - should trigger finding!
    "regular-user": [
        {
            "UserName": "regular-user",
            "SerialNumber": "arn:aws:iam::123456789012:mfa/regular-user",
            "EnableDate": datetime(2023, 6, 15, 10, 0, 0, tzinfo=UTC),
        }
    ],
    "dormant-user": [],
    "service-account": [],
}

# Mock access key last used
MOCK_ACCESS_KEY_LAST_USED = {
    "admin-user": {
        "AccessKeyId": "AKIAEXAMPLE11111",
        "LastUsedDate": datetime.now(UTC) - timedelta(days=1),
        "ServiceName": "iam",
        "Region": "us-east-1",
    },
    "regular-user": {
        "AccessKeyId": "AKIAEXAMPLE22222",
        "LastUsedDate": datetime.now(UTC) - timedelta(days=7),
        "ServiceName": "s3",
        "Region": "us-east-1",
    },
    "dormant-user": {
        "AccessKeyId": "AKIAEXAMPLE33333",
        "LastUsedDate": datetime.now(UTC) - timedelta(days=180),  # Dormant!
        "ServiceName": "s3",
        "Region": "us-east-1",
    },
    "service-account": {
        "AccessKeyId": "AKIAEXAMPLE44444",
        "LastUsedDate": datetime.now(UTC) - timedelta(hours=2),
        "ServiceName": "dynamodb",
        "Region": "us-east-1",
    },
}

# Mock groups
MOCK_GROUPS = {
    "admin-user": [
        {
            "GroupName": "Administrators",
            "GroupId": "AGPAEXAMPLE1111",
            "Arn": "arn:aws:iam::123456789012:group/Administrators",
        },
    ],
    "regular-user": [
        {
            "GroupName": "Developers",
            "GroupId": "AGPAEXAMPLE2222",
            "Arn": "arn:aws:iam::123456789012:group/Developers",
        },
    ],
    "dormant-user": [],
    "service-account": [
        {
            "GroupName": "ServiceAccounts",
            "GroupId": "AGPAEXAMPLE3333",
            "Arn": "arn:aws:iam::123456789012:group/ServiceAccounts",
        },
    ],
}

# Mock user tags
MOCK_USER_TAGS = {
    "admin-user": [
        {"Key": "Department", "Value": "IT"},
        {"Key": "Email", "Value": "admin@example.com"},
    ],
    "regular-user": [
        {"Key": "Department", "Value": "Engineering"},
        {"Key": "Team", "Value": "Backend"},
        {"Key": "Email", "Value": "developer@example.com"},
    ],
    "dormant-user": [
        {"Key": "Department", "Value": "Former Employee"},
    ],
    "service-account": [
        {"Key": "Environment", "Value": "Production"},
        {"Key": "Service", "Value": "OrderProcessor"},
    ],
}
