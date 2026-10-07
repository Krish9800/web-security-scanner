"""Target configuration and scope definition models."""

from pydantic import BaseModel, Field


class ScanTarget(BaseModel):
    """Specification of an authorized target endpoint and its scan parameters."""

    url: str = Field(..., description="Target base URL to assess")
    authorized_by: str = Field(
        default="Authorized Security Auditor",
        description="Operator authorization identity",
    )
    scope_allowlist: list[str] = Field(
        default_factory=list,
        description="Explicit allowed domain or IP boundaries",
    )
    custom_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Custom headers (e.g. Authorization, Cookie) for authenticated scans",
    )
    cookies: dict[str, str] = Field(
        default_factory=dict,
        description="Custom cookies to supply with requests",
    )
    timeout: float = Field(
        default=8.0,
        ge=0.5,
        le=60.0,
        description="Per-request timeout in seconds",
    )
