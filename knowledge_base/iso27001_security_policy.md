# ISO 27001 & OpenEdge Security Compliance Baseline

## 1. Access Control & Authentication Policy (A.9)
- All administrative access, especially root or superuser accounts (e.g., dmin_root), must enforce multi-factor authentication and strict IP subnet restrictions.
- Multiple failed login attempts (e.g., FAILED_SSH_LOGIN) from untrusted external subnets trigger an immediate security alert and automated account lockout protocols.

## 2. File Integrity & System Hardening (A.12 & A.14)
- Unauthorized read or write access attempts to sensitive system files, backup configurations, or security databases (e.g., /etc/shadow backup files or PAS for OpenEdge keystores) must be logged as High Severity (Severity 2 or 3).
- Production environments must restrict file system permissions using principle of least privilege.
