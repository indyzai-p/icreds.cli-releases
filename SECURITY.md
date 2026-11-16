# Security policy

Do not put tokens, enrollment auth IDs, private keys, secret values, database URLs
or production logs in public issues or pull requests. Use GitHub's private
vulnerability reporting for this repository when enabled. If it is unavailable,
request a private reporting channel from the repository owner without disclosing
the vulnerability or credentials publicly. Rotate exposed credentials immediately.

Report the affected package/version, sanitized reproduction, expected/observed
behavior and impact privately. The maintainers must enable a private reporting
channel before the first supported SDK release. No response-time promise or
compliance certification is made by this policy.

Only explicitly published supported SDK versions have a support commitment.
Reserved/planned SDK directories are not released software. Keep HTTPS certificate
verification, JWE and device identity validation enabled; report downgrade,
cross-tenant access, replay, secret logging or package-source disclosure promptly.
