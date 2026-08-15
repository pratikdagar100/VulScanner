# Security model

VulScanner is a defensive security product. This document states what it will
and will not do, how it protects the data it collects, and how it is secured as
an application.

---

## Product boundaries

These are absolute. They are enforced in code, covered by tests, and are not
configurable.

### VulScanner does not

| Never | Why |
|---|---|
| Execute exploits | Findings are evidence of a weakness, not a demonstration of it |
| Collect passwords or password hashes | An assessment tool has no legitimate need for credential material |
| Read or export private keys | Certificate auditing records metadata only |
| Dump credentials, tokens or LSASS memory | This is attacker tradecraft, not assessment |
| Bypass authentication | Access is only ever through documented management interfaces |
| Install persistence | No agent, service, task or autorun entry is created on a target |
| Use stealth, evasion or fragmentation | An authorized assessment should be visible to defenders |
| Disable or reconfigure security software | Defender, the firewall and EDR are read, never touched |
| Scan destructively | Probes are ordinary TCP connects, never malformed or flooding traffic |
| Apply remediation automatically | Commands are guidance; the operator decides and executes |

### VulScanner does

- read Windows state through PowerShell, CIM/WMI and the registry;
- read listening sockets, shares, the neighbour cache and routing tables;
- perform full TCP connect probes against explicitly authorized scopes;
- query NVD and the CISA KEV catalogue for vulnerability intelligence;
- record every finding with the evidence and timestamp that produced it.

---

## The authorization boundary

Nothing is scanned unless the operator has declared it in scope.

```
VULSCANNER_AUTHORIZED_SCOPES=127.0.0.0/8,192.168.0.0/16,10.0.0.0/8
```

`authorize_target()` runs **before any packet is sent**:

- `local` / `localhost` is always permitted;
- an address must fall inside an authorized network;
- a CIDR must be a subnet of an authorized network — requesting a wider range
  than the one authorized is refused;
- a hostname must resolve into an authorized network, or be listed explicitly;
- a hostname that cannot be resolved is refused, because authorization cannot be
  verified.

Refusals return `403` with `error: target_not_authorized` and are written to the
audit log with the actor and the requested target.

Targets may be registered at runtime with an attestation recording who granted
permission — the note is mandatory:

```json
{
  "value": "10.20.0.0/24",
  "authorized": true,
  "authorization_note": "Approved by J. Smith, ticket SEC-1042, valid to 2026-12-31"
}
```

---

## Handling sensitive data

### Secrets are redacted at detection

The PowerShell history and environment collectors look for credential patterns —
plaintext password parameters, API keys, bearer tokens, connection strings, URLs
with embedded credentials, private key headers, AWS and GitHub tokens.

When one matches, VulScanner records **that** a secret is exposed, in which file
and on which line, with the matched value replaced by `[REDACTED]` before the
result leaves the collector. The secret is never stored in the database, written
to a log, or included in a report.

```json
{
  "type": "plaintext-password-parameter",
  "file": "C:\\Users\\...\\ConsoleHost_history.txt",
  "line_number": 412,
  "redacted_line": "Connect-Service -User svc -Password [REDACTED]",
  "explanation": "A password was supplied as a plaintext command-line parameter."
}
```

The same applies to the Winlogon auto-logon check: VulScanner records that a
`DefaultPassword` value **exists**, and deliberately does not read it.

### Remote credentials

Credentials supplied for a remote assessment are:

- accepted only over the API request body or an interactive CLI prompt — the CLI
  refuses a password passed as an argument, where it would be visible in the
  process list and shell history;
- passed to PowerShell through the child process **environment block**, never on
  a command line;
- held in memory for the duration of the scan;
- never persisted, logged or included in a report.

### Filesystem auditing

The filesystem collector reads **metadata only**: name, path, size, timestamps,
extension, owner, signature status and optionally a SHA-256 hash. File contents
are never read, stored or transmitted. Scanning is bounded by a file count, a
directory depth and an exclusion list.

### Logging

Log records pass through a redaction filter that strips values following
credential-like keys. The audit log applies the same filter, and additionally
replaces any field whose name resembles a credential with `[REDACTED]`.

---

## Application security

### Authentication

- Passwords are hashed with bcrypt at cost 12; the 72-byte limit is enforced
  rather than silently truncated.
- Password policy: minimum 12 characters with upper case, lower case, a digit
  and a symbol.
- JWTs are HS256, carry issuer, issued-at, not-before, expiry, a unique `jti`
  and a token type. A refresh token cannot be used as an access token.
- Login verification runs a hash comparison even for an unknown user, so timing
  does not disclose which usernames exist.
- The application refuses to start in production without an explicit
  `VULSCANNER_SECRET_KEY`.

### Authorization

Role-based access control is enforced by a capability matrix, not scattered
role checks. Any capability not explicitly listed defaults to administrator.

| Capability | Minimum role |
|---|---|
| `scan:read`, `finding:read`, `asset:read`, `report:read` | viewer |
| `scan:create`, `finding:update`, `report:create`, `target:create` | analyst |
| `finding:accept_risk`, `user:manage`, `audit:read`, `target:delete` | administrator |

### Transport and headers

Every response carries `X-Content-Type-Options`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, `Permissions-Policy`,
`Cross-Origin-Opener-Policy` and a restrictive `Content-Security-Policy`. HSTS
is added in production. CORS is restricted to the configured origins.

### Rate limiting

Sliding-window limits on login (10 / 5 min), scan creation (30 / 5 min) and the
API overall (600 / min), with `Retry-After` on rejection.

### Input validation

All request bodies are Pydantic models with explicit constraints. Port ranges,
CIDRs and collector names are parsed and validated rather than interpolated.
The PowerShell runner cannot execute an operator-supplied string: scripts come
from VulScanner's own modules or the bundled library, and script paths that
escape that directory are refused.

### Reports

Report downloads resolve the stored path and confirm it is inside the configured
report directory before serving, so a manipulated path cannot read arbitrary
files.

---

## Deployment guidance

1. **Set a real secret key.** Generate with
   `python -c "import secrets; print(secrets.token_urlsafe(64))"`.
2. **Narrow the authorized scopes** to the networks you are actually permitted
   to assess. The defaults are lab-convenient, not an authorization decision.
3. **Terminate TLS in front of the API.** VulScanner speaks HTTP; put nginx,
   IIS or a load balancer in front of it for anything beyond localhost.
4. **Use PostgreSQL in production**, with the database on its own host or
   network segment.
5. **Change the bootstrap administrator password immediately**, and create
   individual accounts with the least role that suffices.
6. **Protect the report directory** — reports contain a detailed map of your
   weaknesses and should be treated as sensitive.
7. **Ship the audit log** to your SIEM. It is append-only by design.
8. **Restrict WinRM** on assessment targets to the scanning host's address.

---

## Reporting a vulnerability

If you find a security issue in VulScanner, please report it privately to the
maintainers rather than opening a public issue. Include the version, the
affected component and reproduction steps.
