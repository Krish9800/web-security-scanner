# Threat Model: Web Security Scanner

## 1. Scope & Asset Classification

This threat model analyzes the security boundaries, operational hazards, and risk vectors associated with deploying and running `web-security-scanner`.

### Primary Assets
1. **Host Infrastructure**: The machine or container executing the scanner.
2. **Target Web Infrastructure**: The systems and web services being assessed.
3. **Scan Assessment Reports**: Vulnerability details, CVSS scores, and remediation intelligence.
4. **Network Perimeter**: Local network interfaces and routing tables.

---

## 2. STRIDE Threat Analysis

| Threat Category | Potential Attack Vector | Impact | Mitigations in web-security-scanner |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker spoofs target domain or uses DNS rebinding to target internal resources. | High | Strict `ScopeGuardian` domain parsing, pre-request DNS resolution verification, and hostname boundary checks. |
| **Tampering** | Injected payloads in query parameters alter state or trigger SQL modifications. | High | Scanner uses exclusively non-destructive canary strings and read-only syntax probes; no `DROP`, `UPDATE`, or destructive SQL statements are executed. |
| **Repudiation** | Lack of scan session audit trail. | Medium | Unique UUID `scan_id`, UTC start and end timestamps recorded in every report. |
| **Information Disclosure** | Vulnerability reports containing sensitive evidence leaked to unauthorized parties. | High | Strict file permissions on report generation; reports default to local terminal unless written to explicit paths. Microservice runs behind authenticated boundaries. |
| **Denial of Service** | Unbounded scanning rate floods target web server, causing downtime. | High | Token-bucket rate limiter (`rate_limit_rps`) and concurrency bounding via `asyncio.Semaphore`. |
| **Elevation of Privilege / SSRF** | Target server responds with HTTP 302 redirect pointing to AWS instance metadata (`169.254.169.254`) or internal IP. | Critical | `AsyncRequester` intercepts each redirect hop; `ScopeGuardian.assert_in_scope()` blocks out-of-scope redirection hops before requests are dispatched. |

---

## 3. ReDoS (Regular Expression Denial of Service) Protection

All regular expressions used for signature matching and HTML link extraction are audited against catastrophic backtracking:
- `HREF_REGEX` uses non-greedy negated character classes `[^"\'\s>]+`.
- SQL error signatures use anchored/bounded keywords without nested quantifiers.
- Unit and adversarial test suites enforce execution deadlines ($< 100\text{ms}$) against $50\text{KB}+$ repetitive inputs.

---

## 4. Container & Process Isolation

- **Rootless execution**: Container runs under unprivileged UID `10001:10001`.
- **Read-only root filesystem**: Read-only rootfs with isolated non-executable `tmpfs` mounts.
- **Capabilities dropped**: `cap_drop: [ALL]`, `no-new-privileges: true`.
