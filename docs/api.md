# REST API

Base URL: `http://localhost:8000`
Interactive documentation: `/api/docs` (Swagger UI) and `/api/redoc`.
Machine-readable schema: `/api/openapi.json`.

---

## Authentication

VulScanner issues a short-lived access token and a longer-lived refresh token.

```http
POST /api/auth/login
Content-Type: application/json

{ "username": "admin", "password": "..." }
```

```json
{
  "access_token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi...",
  "token_type": "bearer",
  "expires_in": 3600,
  "role": "administrator",
  "username": "admin",
  "must_change_password": true
}
```

Send the access token on every subsequent request:

```http
Authorization: Bearer <access_token>
```

| Endpoint | Purpose |
|---|---|
| `POST /api/auth/login` | Exchange credentials for tokens |
| `POST /api/auth/refresh` | Exchange a refresh token for a new pair |
| `POST /api/auth/logout` | Record the logout in the audit trail |
| `GET /api/auth/me` | Current user |
| `POST /api/auth/change-password` | Change your own password |
| `GET /api/auth/users` | List users (administrator) |
| `POST /api/auth/users` | Create a user (administrator) |
| `PATCH /api/auth/users/{id}` | Update a user (administrator) |

Login is rate limited to 10 attempts per 5 minutes per source address; the API
as a whole to 600 requests per minute; scan creation to 30 per 5 minutes.

---

## Roles

| Role | Can |
|---|---|
| `viewer` | Read dashboards, assets, findings, vulnerabilities, network data and reports |
| `analyst` | Everything a viewer can, plus create and cancel scans, triage findings, generate reports, register targets |
| `administrator` | Everything, plus user management, target deletion, risk acceptance and audit log access |

A request without the required capability returns `403` naming the permission.

---

## Scans

```http
POST /api/scans
{
  "name": "Monthly workstation audit",
  "target": "local",
  "profile": "full",
  "options": {
    "network_discovery": true,
    "discovery_scope": "192.168.1.0/24",
    "discovery_profile": "safe",
    "ports": "22,80,443,3389",
    "banner_grab": false,
    "vulnerability_correlation": true,
    "query_windows_update": true
  },
  "credential": { "username": "DOMAIN\\admin", "password": "..." }
}
```

`credential` is used for the duration of the scan and is never persisted,
logged or included in a report.

| Endpoint | Purpose |
|---|---|
| `GET /api/scans` | List scans (`status`, `target`, `limit`, `offset`) |
| `GET /api/scans/{id}` | Scan detail including stages, warnings and collector results |
| `GET /api/scans/{id}/results` | Raw collector evidence (`?collector=defender`) |
| `POST /api/scans/{id}/cancel` | Request cancellation |
| `DELETE /api/scans/{id}` | Delete a scan and its data (administrator) |
| `GET /api/scans/profiles` | Profiles and the collectors each one runs |
| `GET /api/scans/collectors` | Every collector, its category and privilege needs |

### An unauthorized target is refused

```json
HTTP 403
{
  "detail": "Address 8.8.8.8 is not inside an authorized scope. ...",
  "error": "target_not_authorized",
  "guidance": "VulScanner only assesses targets inside a configured authorized scope. ..."
}
```

Nothing is sent to the target, and the refusal is written to the audit log.

---

## Live scan progress

Three mechanisms, all carrying the same event shape.

**Server-Sent Events**

```http
GET /api/scans/{id}/stream
Authorization: Bearer <token>
```

```
data: {"scan_id": 12, "stage": "defender", "progress": 24.4, "message": "Collecting ...", "status": "running"}
```

**WebSocket** — browsers cannot set headers on the handshake, so the token is a
query parameter:

```
ws://localhost:8000/api/scans/{id}/ws?token=<access_token>
```

**Polling snapshot** — the fallback used when neither is available:

```http
GET /api/scans/{id}/progress
```

---

## Assets

| Endpoint | Purpose |
|---|---|
| `GET /api/assets` | Search by `search` (hostname/IP/MAC/vendor), `severity`, `os_name`, `port`, `cve`, `finding_rule` |
| `GET /api/assets/{id}` | Asset detail |
| `GET /api/assets/{id}/findings` | Findings for one asset |
| `GET /api/assets/{id}/ports` | Listening ports for one asset |
| `PATCH /api/assets/{id}/criticality` | Set importance — feeds the risk score |

---

## Findings

| Endpoint | Purpose |
|---|---|
| `GET /api/findings` | Filter by `scan_id`, `asset_id`, `severity`, `category`, `status`, `rule_id`, `search` |
| `GET /api/findings/{id}` | Full finding with evidence and risk factors |
| `PATCH /api/findings/{id}` | Triage: `resolved`, `reopened`, `risk_accepted`, `false_positive` |
| `GET /api/findings/summary` | Counts by severity, category and status |
| `GET /api/findings/remediation` | Ordered remediation plan |

Accepting risk requires the administrator role **and** a justification note;
both are recorded in the audit log.

---

## Vulnerabilities and patches

| Endpoint | Purpose |
|---|---|
| `GET /api/vulnerabilities` | Filter by `scan_id`, `asset_id`, `severity`, `kev`, `product`, `cve_id` |
| `GET /api/vulnerabilities/{id}` | One correlated vulnerability |
| `GET /api/vulnerabilities/cve/{cve_id}` | Cached CVE intelligence, fetched from NVD on a miss |
| `GET /api/vulnerabilities/intelligence` | Intelligence availability and rate limits |
| `GET /api/patches` | Installed and missing updates (`state=installed\|missing`) |

Every vulnerability record carries both the **official CVSS** and the
**VulScanner risk score**, plus the evidence and match method that linked it to
the asset.

---

## Network

| Endpoint | Purpose |
|---|---|
| `GET /api/network/topology` | Graph with per-edge confidence (`?scan_id=`) |
| `GET /api/network/hosts` | Discovered hosts |
| `GET /api/network/ports` | Listening ports (`exposure`, `port`, `protocol`) |
| `GET /api/network/connections` | Observed TCP connections |
| `GET /api/network/services` | Exposed services aggregated across the estate |

Every topology edge carries `confidence`: `observed` (neighbour cache, routing
table, imported LLDP/CDP) or `inferred` (deduced from IP addressing).

---

## Reports

```http
POST /api/reports
{ "scan_id": 12, "format": "pdf" }
```

| Endpoint | Purpose |
|---|---|
| `GET /api/reports` | List generated reports |
| `GET /api/reports/{id}` | Report metadata |
| `GET /api/reports/{id}/download` | Download the file |
| `DELETE /api/reports/{id}` | Delete a report and its file |

Downloads are served only from the configured report directory; a path outside
it is refused.

---

## Dashboard, targets and audit

| Endpoint | Purpose |
|---|---|
| `GET /api/dashboard` | Every dashboard aggregate, computed from stored evidence |
| `GET /api/targets` | Registered authorized targets |
| `POST /api/targets` | Register a target with an authorization attestation |
| `DELETE /api/targets/{id}` | Remove a target (administrator) |
| `GET /api/audit` | Audit log (`action`, `actor`, `outcome`) — administrator |
| `GET /api/health` | Liveness and capability probe (public) |

---

## Errors

| Status | Meaning |
|---|---|
| 400 | Invalid request (for example, accepting risk with no justification) |
| 401 | Missing, expired or invalid token |
| 403 | Insufficient role, or a target outside the authorized scope |
| 404 | Resource not found |
| 409 | Conflict (cancelling a finished scan, duplicate target) |
| 422 | Schema validation failed |
| 429 | Rate limit exceeded — see `Retry-After` |
| 500 | Server error |

---

## Example session

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}' | jq -r .access_token)

SCAN=$(curl -s -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"target":"local","profile":"standard"}' | jq -r .id)

curl -N -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/scans/$SCAN/stream

curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/api/findings?scan_id=$SCAN&severity=critical" | jq .

curl -s -X POST http://localhost:8000/api/reports \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"scan_id\":$SCAN,\"format\":\"pdf\"}" | jq .
```
