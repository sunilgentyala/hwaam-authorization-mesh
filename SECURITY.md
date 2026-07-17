# Security Policy

## Supported versions

Version 0.1.x is the current reference release.

## Reporting a vulnerability

Do not include exploit details, secrets, production policies, or personal information in a public issue.

Use GitHub private vulnerability reporting after it is enabled for the repository:

1. Open the repository.
2. Select **Security**.
3. Select **Advisories**.
4. Select **Report a vulnerability**.

Include:

- Affected version
- Authorization decision that was expected
- Authorization decision that occurred
- Minimal sanitized policy and request
- Reproduction steps
- Potential tenant, privilege, delegation, or audit impact

## Scope

Security reports are especially important for:

- Cross-tenant access
- Authority expansion through delegation
- Mission bypass
- Revocation bypass
- Fail-open behavior
- Receipt forgery
- Policy parsing inconsistencies
- CLI secret exposure
