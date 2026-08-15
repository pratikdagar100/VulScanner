# Installation

## Requirements

| Component | Requirement | Notes |
|---|---|---|
| Operating system | Windows 10, Windows 11, current supported builds | Windows collection needs a Windows host |
| Python | 3.11 or newer | 3.12 recommended |
| PowerShell | Windows PowerShell 5.1 or PowerShell 7+ | Present by default on Windows |
| Node.js | 18 or newer | Web application only |
| Privileges | Administrator recommended | See *Privileges* below |
| Disk | ~500 MB | Dependencies, CVE cache and reports |

VulScanner also runs on Linux and macOS for the API, dashboard, reporting and
network discovery — but the Windows collectors are skipped there, and the health
endpoint reports `windows_collection_available: false`.

---

## Install

```powershell
git clone https://github.com/pratikdagar100/VulScanner.git
cd VulScanner
.\scripts\install.ps1
```

The installer:

1. verifies Python, PowerShell and Node;
2. reports whether the session is elevated;
3. creates `.venv` and installs the backend dependencies;
4. copies `.env.example` to `.env` **with a generated signing key**;
5. creates `logs/`, `cache/cve/` and `reports/generated/`;
6. applies the Alembic migrations;
7. installs the frontend dependencies;
8. verifies the CLI starts.

It is idempotent — re-running it repairs a partial install. Use `-Force` to
recreate the virtual environment, or `-SkipFrontend` for a CLI/API-only install.

```powershell
# Command prompt equivalent
scripts\install.bat
```

---

## Start

```powershell
.\scripts\start.ps1                 # API on :8000, web app on :5173
.\scripts\start.ps1 -ApiOnly        # headless
.\scripts\start.ps1 -Production     # bind 0.0.0.0, serve the built frontend
```

| Service | URL |
|---|---|
| Web application | http://localhost:5173 |
| API | http://localhost:8000 |
| API documentation | http://localhost:8000/api/docs |

### First sign-in

The bootstrap administrator password is generated on first start and printed
**once**, in the API console:

```
====================================================================
  VulScanner bootstrap administrator created
    username: admin
    password: 8Kx-vT2mQp...
  Store this now - it cannot be recovered. Change it after login.
====================================================================
```

It is never written to a log file. If you lose it, delete the database and
re-run, or create a user with `POST /api/auth/users` from an existing admin
session. In production, set `VULSCANNER_BOOTSTRAP_ADMIN_PASSWORD` instead.

---

## Configuration

Everything is environment driven, via `.env` or real environment variables.

### Required in production

```ini
VULSCANNER_ENV=production
VULSCANNER_SECRET_KEY=<64+ random characters>
```

Generate a key with:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

The application **refuses to start in production without a secret key**. In
development it generates an ephemeral one, so tokens do not survive a restart.

### Authorization scope

```ini
VULSCANNER_AUTHORIZED_SCOPES=127.0.0.0/8,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
```

VulScanner refuses any target outside this list. Narrow it to the networks you
are actually authorized to assess — the defaults are broad private ranges
convenient for a lab, not a considered authorization decision.

Individual targets can be registered at runtime with an attestation:

```http
POST /api/targets
{
  "name": "Lab network",
  "value": "10.20.0.0/24",
  "authorized": true,
  "authorization_note": "Approved by J. Smith, ticket SEC-1042, valid to 2026-12-31"
}
```

The note is mandatory and is written to the audit log.

### Database

```ini
# Development (default)
VULSCANNER_DATABASE_URL=sqlite:///./vulscanner.db

# Production
VULSCANNER_DATABASE_URL=postgresql+psycopg://vulscanner:PASSWORD@localhost:5432/vulscanner
```

Apply migrations after changing the URL:

```powershell
cd backend
..\.venv\Scripts\python.exe -m alembic upgrade head
```

### Vulnerability intelligence

```ini
VULSCANNER_NVD_API_KEY=
VULSCANNER_CVE_ONLINE=true
VULSCANNER_CVE_CACHE_TTL_HOURS=24
```

An NVD API key is free and strongly recommended: without one, NVD limits you to
one request every six seconds, which caps how many products can be correlated
per scan. Request one at
<https://nvd.nist.gov/developers/request-an-api-key>.

Set `VULSCANNER_CVE_ONLINE=false` for fully offline operation — correlation then
uses only the local cache, and the UI reports intelligence as offline.

### MAC vendor resolution

VulScanner ships with a small built-in OUI table. For full coverage, drop the
IEEE registry export at `cache/oui.csv`:

```powershell
curl -o cache\oui.csv https://standards-oui.ieee.org/oui/oui.csv
```

`vulscanner version` reports how many vendor entries are loaded.

---

## Privileges

VulScanner runs without administrative rights, but several collectors need them
to read their data completely:

| Collector | Without elevation |
|---|---|
| `defender` | Exclusions and preferences unavailable |
| `audit_policy` | `auditpol` returns nothing |
| `group_policy` | `secedit /export` fails |
| `firewall` | Rule detail may be reduced |
| `secure_boot` | TPM and BitLocker state may be unavailable |

Missing data is reported as a **warning on the affected collector** — never
assumed to be an insecure setting. To run elevated, start PowerShell with *Run as
Administrator* before `.\scripts\start.ps1`.

---

## Remote scanning prerequisites

Remote assessment uses WinRM. On the **target** host, as an administrator:

```powershell
# Enable WinRM
Enable-PSRemoting -Force

# Confirm the listener
Get-Item WSMan:\localhost\Listener\*\Port

# Permit the scanning host through the firewall (scope it to your subnet)
Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP' -RemoteAddress 192.168.1.0/24
```

The scanning account must be a member of **Administrators** (full collection) or
**Remote Management Users** (reduced collection).

For a workgroup (non-domain) target, add the target to the scanning host's
TrustedHosts list:

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '192.168.1.25' -Concatenate
```

Then scan:

```powershell
vulscanner scan --target 192.168.1.25 --profile standard --username admin --ask-password
```

The CLI **never accepts a password as an argument** — `--ask-password` prompts
for it, and the value is held in memory only for the duration of the scan.

---

## Docker

The container runs the management plane: API, database, dashboard and
reporting, plus network discovery of scopes it can route to. Windows collection
requires a Windows host.

```bash
cp .env.example .env
# set VULSCANNER_SECRET_KEY, POSTGRES_PASSWORD and VULSCANNER_AUTHORIZED_SCOPES

cd frontend && npm install && npm run build && cd ..
docker compose up -d
```

The dashboard is then on <http://localhost:8080> and the API on
<http://localhost:8000>.

Bind those ports to a private interface. The API is an authenticated scanning
engine and must never be published to the internet - see
[deployment.md](deployment.md) for what can and cannot be hosted.

---

## Building `vulscanner.exe`

```powershell
.\scripts\build.ps1
.\dist\vulscanner.exe version
```

PyInstaller produces a single-file executable that needs no Python installation
on the machine that runs it. Add `dist\` to `PATH` to run `vulscanner` from
anywhere.

To produce a full release archive (executable, web bundle, docs, scripts and
SHA256 checksum):

```powershell
.\scripts\package.ps1
```

---

## Verifying the installation

```powershell
.\scripts\vulscanner.ps1 version          # capability report
.\scripts\vulscanner.ps1 scan local --profile quick
.venv\Scripts\python.exe -m pytest backend/tests -q
curl http://localhost:8000/api/health
```

`vulscanner version` reports whether Windows collection is available, whether
the session is elevated, how many collectors are registered and which scopes are
authorized.
