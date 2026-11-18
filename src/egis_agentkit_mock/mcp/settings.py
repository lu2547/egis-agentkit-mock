"""读取并校验 MCP Mock 的地址、认证和运行配置。"""

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, PositiveInt, model_validator


class SettingsModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TLSSettings(SettingsModel):
    certificate: Path
    private_key: Path
    ca_certificate: Path
    ca_private_key: Path
    valid_days: PositiveInt


class OAuthSettings(SettingsModel):
    code_lifetime_seconds: PositiveInt
    consent_lifetime_seconds: PositiveInt
    access_lifetime_seconds: PositiveInt
    refresh_lifetime_seconds: PositiveInt
    scopes: list[str] = Field(min_length=1)
    redirect_uris: list[str] = Field(min_length=1)


class InstanceSettings(SettingsModel):
    name: Literal["reports", "directory"]
    display_name: str
    description: str
    oauth_port: int = Field(ge=1, le=65535)
    mcp_port: int = Field(ge=1, le=65535)
    public_host: str = "localhost"

    @property
    def issuer(self) -> str:
        return f"https://{self.public_host}:{self.oauth_port}"

    @property
    def resource(self) -> str:
        return f"https://{self.public_host}:{self.mcp_port}/mcp"

    def connector(self) -> dict:
        """返回可提交给管理员连接器接口的配置。"""
        return {
            "resource_id": f"mock-{self.name}",
            "display_name": self.display_name,
            "description": self.description,
            "config": {
                "transport": "streamable_http",
                "url": self.resource,
                "auth_type": "oauth",
            },
        }


class MockSettings(SettingsModel):
    host: Literal["127.0.0.1", "::1"]
    public_host: str
    http_timeout_seconds: PositiveInt
    shutdown_timeout_seconds: PositiveInt
    process_poll_seconds: float = Field(gt=0)
    log_level: Literal["debug", "info", "warning", "error"]
    tls: TLSSettings
    oauth: OAuthSettings
    instances: list[InstanceSettings] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def validate_instances(self):
        ports = [
            port for item in self.instances for port in (item.oauth_port, item.mcp_port)
        ]
        if len(set(ports)) != len(ports):
            raise ValueError("Each MCP and OAuth service requires its own port")
        if len({instance.name for instance in self.instances}) != len(self.instances):
            raise ValueError("MCP instances require distinct names")
        return self


DEFAULT_CONFIG = Path(__file__).with_name("settings.toml")


def load_settings(path: Path = DEFAULT_CONFIG) -> MockSettings:
    with path.open("rb") as source:
        values = tomllib.load(source)
    for instance in values["instances"]:
        instance["public_host"] = values["public_host"]
    return MockSettings.model_validate(values)
