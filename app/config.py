"""Configuration loaded from environment variables / .env."""

from __future__ import annotations

import socket

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration for the webhook bridge."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Inbound auth (what SAO must present) ---------------------------------
    webhook_token: str = Field(default="", description="Bearer token SAO must send.")
    allow_insecure: bool = Field(
        default=False,
        description="Permit an empty webhook_token. Local testing only.",
    )

    # --- Outbound: Splunk HEC -------------------------------------------------
    hec_url: str = Field(
        default="",
        description="HEC base URL, e.g. https://splunk.example.com:8088",
    )
    hec_token: str = Field(default="", description="Splunk HEC token.")
    hec_index: str = Field(default="sao_alerts")
    hec_sourcetype: str = Field(default="splunk:sao:alert")
    hec_source: str = Field(default="sao:webhook")
    hec_host: str = Field(default_factory=socket.gethostname)
    hec_verify_tls: bool = Field(default=True)
    hec_timeout_seconds: float = Field(default=10.0, gt=0)

    # --- SAO console deep links -----------------------------------------------
    # SAO emits deep_link against its own console host, which is not always the
    # console a given tenant actually uses. These rewrite it on the way through;
    # leaving sao_console_url empty disables rewriting entirely.
    sao_console_url: str = Field(
        default="",
        description="Target console origin, e.g. https://console.multitenant.sao.splunkcloud.com",
    )
    sao_tenant: str = Field(
        default="",
        description="Tenant path segment inserted before /project, e.g. your-tenant.",
    )
    sao_stream_segment: str = Field(
        default="agent-streams",
        description="Path segment that replaces 'log-streams' in the deep link.",
    )

    # --- Retry policy ---------------------------------------------------------
    retry_max_attempts: int = Field(default=5, ge=1)
    retry_base_delay: float = Field(default=0.5, gt=0)
    retry_max_delay: float = Field(default=30.0, gt=0)

    # --- Misc -----------------------------------------------------------------
    log_level: str = Field(default="INFO")

    @field_validator("hec_url", "sao_console_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @field_validator("sao_tenant", "sao_stream_segment")
    @classmethod
    def _strip_slashes(cls, v: str) -> str:
        return v.strip("/")

    @property
    def hec_event_url(self) -> str:
        """Full HEC endpoint for structured (JSON envelope) events."""
        return f"{self.hec_url}/services/collector/event"

    def validate_startup(self) -> list[str]:
        """Return a list of fatal configuration problems (empty == OK)."""
        problems: list[str] = []
        if not self.webhook_token and not self.allow_insecure:
            problems.append(
                "WEBHOOK_TOKEN is not set. Set it, or set ALLOW_INSECURE=true "
                "to run without inbound authentication (local testing only)."
            )
        if not self.hec_url:
            problems.append("HEC_URL is not set.")
        if not self.hec_token:
            problems.append("HEC_TOKEN is not set.")
        return problems


def get_settings() -> Settings:
    """Build a Settings instance. Call once at startup; injected elsewhere."""
    return Settings()
