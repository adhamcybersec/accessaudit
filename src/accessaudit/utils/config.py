"""Configuration management for AccessAudit."""

import os
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class AWSConfig(BaseModel):
    """AWS provider configuration."""

    enabled: bool = True
    regions: list[str] = Field(default_factory=lambda: ["us-east-1"])
    access_key_id: str | None = None
    secret_access_key: str | None = None
    profile: str | None = None


class AzureConfig(BaseModel):
    """Azure AD configuration."""

    enabled: bool = False
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


class GCPConfig(BaseModel):
    """GCP IAM configuration."""

    enabled: bool = False
    project_id: str | None = None
    credentials_file: str | None = None


class SailPointBaseConfig(BaseModel):
    """SailPoint provider base configuration (used in ProvidersConfig)."""

    enabled: bool = False
    base_url: str | None = None
    username: str | None = None
    password: str | None = None


class ProvidersConfig(BaseModel):
    """All provider configurations."""

    aws: AWSConfig = Field(default_factory=AWSConfig)
    azure: AzureConfig = Field(default_factory=AzureConfig)
    gcp: GCPConfig = Field(default_factory=GCPConfig)
    sailpoint: SailPointBaseConfig = Field(default_factory=SailPointBaseConfig)


class RuleConfig(BaseModel):
    """Custom rule configuration."""

    name: str
    severity: str
    condition: str
    description: str | None = None
    remediation: str | None = None


class AnalysisConfig(BaseModel):
    """Analysis configuration."""

    dormant_threshold_days: int = 90
    max_permissions_threshold: int = 50
    rules: list[RuleConfig] = Field(default_factory=list)


class ReportingConfig(BaseModel):
    """Reporting configuration."""

    formats: list[str] = Field(default_factory=lambda: ["json"])
    include_remediation: bool = True
    output_dir: str = "./reports"


class DatabaseConfig(BaseModel):
    """Database configuration."""

    url: str | None = None


class RedisConfig(BaseModel):
    """Redis configuration."""

    url: str | None = None


class AuthConfig(BaseModel):
    """Authentication configuration."""

    secret_key: str = "change-me-in-production"
    token_expire_minutes: int = 60
    require_auth: bool = False


class SailPointConfig(BaseModel):
    """SailPoint IIQ configuration."""

    enabled: bool = False
    base_url: str | None = None
    username: str | None = None
    password: str | None = None
    token: str | None = None


class NotificationProviderConfig(BaseModel):
    """Single notification provider configuration."""

    type: str  # slack, teams, webhook
    webhook_url: str
    min_severity: str = "medium"
    events: list[str] = Field(default_factory=lambda: ["scan_completed", "critical_finding"])


class NotificationConfig(BaseModel):
    """Notification system configuration."""

    enabled: bool = False
    providers: list[NotificationProviderConfig] = Field(default_factory=list)


class Config(BaseSettings):
    """Main AccessAudit configuration."""

    providers: ProvidersConfig = Field(default_factory=ProvidersConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)

    class Config:
        """Pydantic settings configuration."""

        env_prefix = "ACCESSAUDIT_"
        env_nested_delimiter = "__"

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return self.model_dump()


def load_config(config_path: str | Path | None = None) -> Config:
    """Load configuration from file and environment.

    Args:
        config_path: Path to YAML config file (optional)

    Returns:
        Config object
    """
    config_data: dict[str, Any] = {}

    # Load from file if provided
    if config_path:
        config_path = Path(config_path)
        if config_path.exists():
            with open(config_path) as f:
                file_config = yaml.safe_load(f) or {}
                config_data.update(file_config)
        else:
            print(f"Warning: Config file not found: {config_path}")

    # Override with environment variables
    config_data = _apply_env_overrides(config_data)

    # Create config object
    try:
        config = Config(**config_data)
    except Exception as e:
        print(f"Warning: Invalid config, using defaults: {e}")
        config = Config()

    return config


def _apply_env_overrides(config: dict[str, Any]) -> dict[str, Any]:
    """Apply environment variable overrides to config.

    Args:
        config: Base configuration dictionary

    Returns:
        Config with env overrides applied
    """
    # AWS credentials from standard env vars
    if "providers" not in config:
        config["providers"] = {}
    if "aws" not in config["providers"]:
        config["providers"]["aws"] = {}

    aws_config = config["providers"]["aws"]

    if os.environ.get("AWS_ACCESS_KEY_ID"):
        aws_config["access_key_id"] = os.environ["AWS_ACCESS_KEY_ID"]
    if os.environ.get("AWS_SECRET_ACCESS_KEY"):
        aws_config["secret_access_key"] = os.environ["AWS_SECRET_ACCESS_KEY"]
    if os.environ.get("AWS_DEFAULT_REGION"):
        aws_config["regions"] = [os.environ["AWS_DEFAULT_REGION"]]
    if os.environ.get("AWS_PROFILE"):
        aws_config["profile"] = os.environ["AWS_PROFILE"]

    # Azure credentials
    if "azure" not in config["providers"]:
        config["providers"]["azure"] = {}

    azure_config = config["providers"]["azure"]

    if os.environ.get("AZURE_TENANT_ID"):
        azure_config["tenant_id"] = os.environ["AZURE_TENANT_ID"]
    if os.environ.get("AZURE_CLIENT_ID"):
        azure_config["client_id"] = os.environ["AZURE_CLIENT_ID"]
    if os.environ.get("AZURE_CLIENT_SECRET"):
        azure_config["client_secret"] = os.environ["AZURE_CLIENT_SECRET"]

    # GCP credentials
    if "gcp" not in config["providers"]:
        config["providers"]["gcp"] = {}

    gcp_config = config["providers"]["gcp"]

    if os.environ.get("GOOGLE_CLOUD_PROJECT"):
        gcp_config["project_id"] = os.environ["GOOGLE_CLOUD_PROJECT"]
    if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        gcp_config["credentials_file"] = os.environ["GOOGLE_APPLICATION_CREDENTIALS"]

    # Database URL
    if os.environ.get("DATABASE_URL"):
        if "database" not in config:
            config["database"] = {}
        config["database"]["url"] = os.environ["DATABASE_URL"]

    # Redis URL
    if os.environ.get("REDIS_URL"):
        if "redis" not in config:
            config["redis"] = {}
        config["redis"]["url"] = os.environ["REDIS_URL"]

    # Auth secret key
    if os.environ.get("AUTH_SECRET_KEY"):
        if "auth" not in config:
            config["auth"] = {}
        config["auth"]["secret_key"] = os.environ["AUTH_SECRET_KEY"]

    return config


def create_example_config(output_path: str | Path = "config.example.yaml") -> None:
    """Create an example configuration file.

    Args:
        output_path: Path to write example config
    """
    example_config = """# AccessAudit Configuration
# Copy to config.yaml and customize

providers:
  aws:
    enabled: true
    regions:
      - us-east-1
      - eu-west-1
    # Credentials (optional - uses environment variables or IAM roles if not specified)
    # access_key_id: ${AWS_ACCESS_KEY_ID}
    # secret_access_key: ${AWS_SECRET_ACCESS_KEY}

  azure:
    enabled: false
    # tenant_id: ${AZURE_TENANT_ID}
    # client_id: ${AZURE_CLIENT_ID}
    # client_secret: ${AZURE_CLIENT_SECRET}

  gcp:
    enabled: false
    # project_id: ${GOOGLE_CLOUD_PROJECT}
    # credentials_file: ${GOOGLE_APPLICATION_CREDENTIALS}

analysis:
  dormant_threshold_days: 90
  max_permissions_threshold: 50

  rules:
    - name: "No wildcard admin policies"
      severity: critical
      condition: "policy.is_overly_permissive"
      description: "Policies should not grant wildcard permissions on all resources"
      remediation: "Replace with least-privilege policy based on actual usage"

    - name: "MFA required for privileged accounts"
      severity: high
      condition: "account.has_admin_role AND NOT account.mfa_enabled"
      description: "Administrative accounts must have MFA enabled"
      remediation: "Enable MFA for this account immediately"

reporting:
  formats:
    - json
  include_remediation: true
  output_dir: ./reports
"""

    with open(output_path, "w") as f:
        f.write(example_config)

    print(f"Example config created: {output_path}")
