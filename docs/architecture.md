# Web Security Scanner Architecture Specification

## 1. Executive Architectural Overview

`web-security-scanner` is an enterprise-grade automated web vulnerability scanner and security posture assessment engine. Designed from the ground up for high reliability, zero side-effects, and defensive audit safety, it combines asynchronous token-bucket rate limiting with strict scope boundaries to assess web endpoints without causing service disruption.

```mermaid
flowchart TD
    CLI[Typer CLI / REST API] --> Engine[Scan Orchestrator]
    Engine --> Scope[ScopeGuardian & Sanitizer]
    Engine --> Requester[AsyncRequester Engine]
    Requester --> Throttler[Token-Bucket Throttler & Semaphore]
    
    subgraph "Scanning Module Suite"
        Hdr[Headers Scanner]
        Cookie[Cookie Hygiene Scanner]
        Methods[HTTP Methods Scanner]
        Files[Sensitive Files Discovery]
        XSS[Canary XSS Scanner]
        SQLi[SQLi Syntax Error Scanner]
        CORS[CORS Misconfiguration Scanner]
        Redir[Open Redirect Scanner]
    end
    
    Engine --> Hdr
    Engine --> Cookie
    Engine --> Methods
    Engine --> Files
    Engine --> XSS
    Engine --> SQLi
    Engine --> CORS
    Engine --> Redir

    Engine --> Scorer[Security Scoring & Posture Engine]
    Scorer --> Reports[Report Generators]
    Reports --> JSONOut[JSON Report]
    Reports --> MDOut[Markdown Report]
    Reports --> SARIFOut[SARIF v2.1.0 (GitHub Code Scanning)]
```

---

## 2. Core Components & Subsystems

### 2.1 ScopeGuardian & URLSanitizer
- **ScopeGuardian**: Acts as a strict boundary enforcer preventing unauthorized scans, IP hopping, and SSRF attacks. Evaluates exact domains and wildcard subdomains (`*.domain.tld`).
- **URLSanitizer**: Normalizes schemes (HTTP/HTTPS), strips inline user credentials, normalizes default ports, and rejects null-byte/control character injection attacks.

### 2.2 AsyncRequester
- Asynchronous HTTP engine built atop `httpx.AsyncClient`.
- Implements a thread-safe token-bucket algorithm to enforce precise requests-per-second (`rate_limit_rps`) limits.
- Bounds concurrency via an `asyncio.Semaphore`.
- **SSRF Redirect Inspection**: Every redirect hop is intercepted and re-validated against `ScopeGuardian.is_in_scope()`. If an in-scope endpoint redirects to cloud metadata (`169.254.169.254`) or internal RFC 1918 subnets, `ScopeViolationError` is raised immediately.

### 2.3 Scanner Module Taxonomy
1. **HeadersScanner**: Analyzes HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and server banner leaks.
2. **CookieScanner**: Evaluates session cookies for `Secure`, `HttpOnly`, and `SameSite` flags.
3. **MethodsScanner**: Audits dangerous HTTP verbs (TRACE, PUT, DELETE, OPTIONS).
4. **SensitiveFilesScanner**: Probes exposure of `.env`, `.git/HEAD`, `robots.txt`, `security.txt`, and backup files with content regex signatures to eliminate soft-404 false positives.
5. **XSSScanner**: Injects harmless, unique canary tokens (`<webscan-xss-canary>`) into query parameters to detect unencoded reflection.
6. **SQLiScanner**: Injects standard syntax probes (`'`, `"`, `\`) into parameters and matches against 13 database error signatures (PostgreSQL, MySQL, SQLite, Oracle, MSSQL).
7. **CORSScanner**: Probes with test origins and evaluates wildcard and reflection vulnerabilities with `Access-Control-Allow-Credentials`.
8. **OpenRedirectScanner**: Detects unvalidated external redirection in destination query parameters.

### 2.4 Security Scoring & Posture Engine
- CVSS-aligned quantitative score calculation ($0-100$):
  - Critical: $-25$ points
  - High: $-15$ points
  - Medium: $-7$ points
  - Low: $-2$ points
  - Informational: $0$ points
- Letter Grade categorization:
  - $\ge 90$: **A**
  - $80 - 89$: **B**
  - $70 - 79$: **C**
  - $60 - 69$: **D**
  - $< 60$: **F**

### 2.5 Multi-Format Reporters
- **JSON**: Machine-parsable full serialization.
- **Markdown**: Formatted executive summary, vulnerability table, and remediation advice.
- **SARIF v2.1.0**: OASIS standard schema for native GitHub Advanced Security ingestion.
