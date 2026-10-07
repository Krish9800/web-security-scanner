from typing import ClassVar

from webscan.models.vulnerability import Severity, VulnerabilityCategory, VulnerabilityFinding


class CookieScanner:
    """Audits Set-Cookie headers for missing Secure, HttpOnly, and SameSite flags."""

    SESSION_COOKIE_NAMES: ClassVar[set[str]] = {
        "session",
        "sessionid",
        "phpsessid",
        "jsessionid",
        "asp.net_sessionid",
        "token",
        "auth",
        "authtoken",
        "jwt",
        "access_token",
        "id",
    }

    @classmethod
    def scan_cookies(
        cls,
        target_url: str,
        cookie_headers: list[str],
    ) -> list[VulnerabilityFinding]:
        """Analyze list of Set-Cookie header strings and flag security weaknesses."""
        findings: list[VulnerabilityFinding] = []
        is_https = target_url.lower().startswith("https://")

        for cookie_str in cookie_headers:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts:
                continue

            # First part is name=value
            key_val = parts[0].split("=", 1)
            cookie_name = key_val[0].strip()
            name_lower = cookie_name.lower()

            attributes = {p.lower() for p in parts[1:]}
            attr_keys = {p.split("=")[0].strip().lower() for p in parts[1:]}

            has_secure = "secure" in attributes
            has_httponly = "httponly" in attributes
            has_samesite = "samesite" in attr_keys

            # 1. Missing Secure flag on HTTPS
            if is_https and not has_secure:
                findings.append(
                    VulnerabilityFinding(
                        finding_id="FIND-CK-001",
                        title=f"Cookie Without Secure Flag ({cookie_name})",
                        category=VulnerabilityCategory.COOKIES,
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-614",
                        cvss_score=5.0,
                        target_url=target_url,
                        parameter=cookie_name,
                        evidence=f"Set-Cookie: {cookie_str}",
                        description="Cookie transmitted over HTTPS lacks the 'Secure' attribute.",
                        remediation=f"Append '; Secure' to Set-Cookie for '{cookie_name}'.",
                    )
                )

            # 2. Missing HttpOnly flag on session/auth cookies
            is_sensitive_cookie = any(sub in name_lower for sub in cls.SESSION_COOKIE_NAMES)
            if is_sensitive_cookie and not has_httponly:
                findings.append(
                    VulnerabilityFinding(
                        finding_id="FIND-CK-002",
                        title=f"Sensitive Cookie Without HttpOnly Flag ({cookie_name})",
                        category=VulnerabilityCategory.COOKIES,
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-1004",
                        cvss_score=5.3,
                        target_url=target_url,
                        parameter=cookie_name,
                        evidence=f"Set-Cookie: {cookie_str}",
                        description=(
                            f"Sensitive session cookie '{cookie_name}' lacks 'HttpOnly', "
                            "allowing JavaScript theft via XSS."
                        ),
                        remediation=f"Append '; HttpOnly' to Set-Cookie for '{cookie_name}'.",
                    )
                )

            # 3. Missing or insecure SameSite flag
            if not has_samesite:
                findings.append(
                    VulnerabilityFinding(
                        finding_id="FIND-CK-003",
                        title=f"Cookie Without SameSite Attribute ({cookie_name})",
                        category=VulnerabilityCategory.COOKIES,
                        severity=Severity.LOW,
                        cwe_id="CWE-1275",
                        cvss_score=3.7,
                        target_url=target_url,
                        parameter=cookie_name,
                        evidence=f"Set-Cookie: {cookie_str}",
                        description=(
                            f"Cookie '{cookie_name}' does not specify a SameSite policy, "
                            "increasing CSRF vulnerability."
                        ),
                        remediation=f"Append '; SameSite=Lax' to '{cookie_name}'.",
                    )
                )

        return findings
