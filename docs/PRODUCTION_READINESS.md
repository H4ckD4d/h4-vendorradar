# H4 VendorRadar — Engineering readiness v0.2

Creator and technical direction: **Chris Cruz — @h4ckd4d**.

Implemented for demonstration: tenant-scoped API, three demo roles, hashed high-entropy API key records, denied revoked keys, paginated audit, read-only tenant-scoped expiring evidence report and authorization regression tests.

For local labs, configure H4_TENANTS as JSON containing tenant_id, actor_id, role and key_sha256 (SHA-256 digest of a long randomly generated API key). Plaintext key remains for backward compatibility but is not recommended. Do not commit raw tokens.

Production blockers: OIDC/SSO, full tenant RBAC, DB migrations, PostgreSQL RLS, secret vault, durable event jobs, distributed rate limiting, idempotency, observability, billing, operational monitoring, load testing, recovery drills, legal review, and pilot validation. No commercial readiness or formal certification is claimed.
