# Changelog

All notable changes to `web-security-scanner` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-07

### Added
- **ScopeGuardian & URLSanitizer**: Domain allowlist validation, wildcard matching, null-byte neutralization, and SSRF prevention.
- **AsyncRequester**: Asynchronous HTTP client engine with token-bucket rate limiting and concurrency semaphore.
- **Scanning Engine Suite**:
  - `HeadersScanner`: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and banner disclosures.
  - `CookieScanner`: Secure, HttpOnly, and SameSite attribute verification.
  - `MethodsScanner`: Dangerous HTTP verbs (TRACE, PUT, DELETE, OPTIONS).
  - `SensitiveFilesScanner`: Content signature detection for `.env`, `.git/HEAD`, `robots.txt`, `security.txt`, and database backups.
  - `XSSScanner`: Non-destructive canary token reflection analysis.
  - `SQLiScanner`: Database error disclosure analysis across MySQL, PostgreSQL, SQLite, Oracle, MSSQL.
  - `CORSScanner`: Reflection, wildcards, and credential configuration auditing.
  - `OpenRedirectScanner`: Parameter-based unvalidated destination redirection detection.
- **Security Scoring Engine**: CVSS-weighted quantitative scoring ($0-100$) and letter grades (A through F).
- **Multi-Format Reporters**: Standardized JSON, human-readable Markdown, and OASIS SARIF v2.1.0.
- **Typer & Rich CLI**: Interactive `webscan scan`, `probe`, `lab`, and `version` commands with rich terminal styling.
- **Embedded Security Testing Lab**: Deliberately vulnerable mock server for offline testing and verification.
- **FastAPI Microservice**: REST API with `/health`, `/api/v1/scan`, and `/api/v1/probe` endpoints.
- **DevSecOps Stack**: Multi-stage rootless Dockerfile (UID `10001:10001`), docker-compose, and GitHub Actions CI workflow.
