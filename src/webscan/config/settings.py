"""Application configuration and runtime settings via Pydantic Settings."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for web-security-scanner."""

    model_config = SettingsConfigDict(
        env_prefix="WEBSCAN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = Field(
        default="Web Security Assessment Scanner",
        description="Application title",
    )
    version: str = Field(default="0.1.0", description="Semantic version")
    environment: str = Field(default="development", description="Environment mode")

    default_timeout_seconds: float = Field(
        default=8.0,
        description="Per-request HTTP timeout in seconds",
    )
    max_concurrency: int = Field(
        default=10,
        description="Maximum concurrent asynchronous tasks",
    )
    max_requests_per_second: float = Field(
        default=20.0,
        description="Token bucket rate limit per second",
    )
    user_agent: str = Field(
        default="WebScan-Security-Auditor/0.1.0 (Defensive; Authorized Security Audit)",
        description="HTTP User-Agent string sent during scans",
    )

    allowed_schemes: tuple[str, ...] = ("http", "https")
    default_allowlist: tuple[str, ...] = (
        "localhost",
        "127.0.0.1",
        "::1",
        "testserver",
    )
    enforce_scope: bool = Field(
        default=True,
        description="Strictly block requests outside the configured target scope",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached singleton instance of application settings."""
    return Settings()
