# Security Policy

## Supported Versions

This is a research project. Only the latest commit on `main` is supported.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| Older commits | ❌ |

## Reporting a Vulnerability

If you discover a security vulnerability in this project's code (e.g. a secrets leak, insecure dependency, or exploitable logic in the analysis scripts):

1. **Do NOT open a public GitHub issue.**
2. Email: `security@chandraverse.dev` (or use GitHub's private vulnerability reporting)
3. Include:
   - Description of the vulnerability
   - File and line number
   - Steps to reproduce
   - Potential impact

I will acknowledge within 48 hours and aim to resolve within 7 days.

## Scope

**In scope:**
- Hardcoded secrets or API keys accidentally committed
- Insecure deserialization in analysis scripts
- Command injection vulnerabilities in shell scripts
- Insecure TAXII server configuration

**Out of scope:**
- The honeypot itself intentionally accepts malicious connections — this is by design
- Third-party dependencies (report to upstream maintainers)

## Note on Honeypot Data

All IPs and hashes in sample data files are **anonymised** (last octet replaced with `XX`). No real attacker PII is stored in this repository.
