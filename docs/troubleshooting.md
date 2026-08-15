# Troubleshooting

Start here:

```powershell
.\scripts\vulscanner.ps1 version --verbose
curl http://localhost:8000/api/health
```

`version` reports whether Windows collection is available, whether the session
is elevated, how many collectors are registered and which scopes are authorized
— which resolves most questions immediately.

---

## Installation

### "Python was not found"

Install Python 3.11+ from <https://www.python.org/downloads/> and tick **Add
python.exe to PATH** during setup. Verify with `python --version`.

If Windows opens the Microsoft Store instead, disable the aliases under
*Settings → Apps → Advanced app settings → App execution aliases*.

### "running scripts is disabled on this system"

PowerShell's execution policy is blocking the installer. Either use the batch
wrapper, which bypasses the policy for that process only:

```powershell
scripts\install.bat
```

or run the script explicitly:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

### Dependency installation fails

Usually a proxy or TLS interception. Try:

```powershell
.venv\Scripts\python.exe -m pip install -r backend\requirements.txt --proxy http://proxy:8080
```

### `npm install` fails

The API and CLI do not need Node. Re-run with `-SkipFrontend`, or install
Node 18+ from <https://nodejs.org/> and re-run.

---

## Starting up

### "VULSCANNER_SECRET_KEY must be set in production"

Expected: the application refuses to start in production without a signing key.

```powershell
python -c "import secrets; print(secrets.token_urlsafe(64))"
# put the value in .env as VULSCANNER_SECRET_KEY=...
```

### Port already in use

```powershell
Get-NetTCPConnection -LocalPort 8000 -State Listen | Select-Object OwningProcess
.\scripts\start.ps1 -ApiPort 8001 -WebPort 5174
```

### I lost the bootstrap administrator password

It is printed once and never stored in reversible form. Either create a user
from an existing admin session (`POST /api/auth/users`), or reset the database:

```powershell
Remove-Item vulscanner.db*
.\scripts\start.ps1     # a new password is printed
```

### The dashboard shows "Could not load data"

Confirm the API is up (`curl http://localhost:8000/api/health`). In development
the web app proxies `/api` to `127.0.0.1:8000`; if the API is on another port,
set `VULSCANNER_API_URL` before starting the dev server.

---

## Scanning

### "Target is not inside an authorized scope"

Working as designed — VulScanner refuses anything outside the declared scope.
Either widen `VULSCANNER_AUTHORIZED_SCOPES` in `.env` (and restart), or register
the target with an attestation:

```http
POST /api/targets
{"name":"Lab","value":"10.20.0.0/24","authorized":true,
 "authorization_note":"Approved by ..., ticket ..."}
```

Only add scopes you are genuinely authorized to assess.

### Many collectors report warnings

Most often the session is not elevated. Check:

```powershell
.\scripts\vulscanner.ps1 version    # look at "Privileges"
```

Start PowerShell with *Run as Administrator* and re-run. Collectors that need
elevation are `defender`, `audit_policy`, `group_policy`, `secure_boot` and
parts of `firewall`.

### "Microsoft Defender cmdlets are unavailable"

Expected when Defender is not installed or has been replaced by a third-party
product. The collector is skipped and the `antivirus` collector reports which
product is registered instead.

### Scans are slow

- The `full` profile queries the Windows Update agent, which contacts the
  configured update source and can take minutes. Use `standard` for routine
  scans.
- CVE correlation without an NVD API key is limited to one request every six
  seconds. Configure `VULSCANNER_NVD_API_KEY`, or use `--no-cve`.
- Large discovery scopes take time. Narrow the scope, or use `--profile safe`.

### Network discovery finds nothing

- Host firewalls commonly drop probes; silence does not prove absence.
- Confirm you are on the same network: `.\scripts\vulscanner.ps1 version` shows
  the authorized scopes, and `Get-NetIPAddress` shows your addresses.
- Wireless client isolation blocks host-to-host traffic on many guest networks.
- Try a broader port set: `--profile standard`.

### Remote scan fails to connect

On the target, as administrator:

```powershell
Enable-PSRemoting -Force
Test-WSMan -ComputerName <target>          # run from the scanning host
```

For a workgroup target, add it to TrustedHosts on the **scanning** host:

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '192.168.1.25' -Concatenate
```

The account must be in Administrators or Remote Management Users on the target.

### "Access is denied" during a remote scan

The account lacks rights on the target, or remote UAC token filtering is
blocking a local account. Use a domain account in the local Administrators
group, or a local account that the target explicitly permits.

---

## Vulnerability intelligence

### No CVEs are correlated

Check the intelligence status:

```powershell
.\scripts\vulscanner.ps1 version --verbose
```

Common causes:

- `VULSCANNER_CVE_ONLINE=false`, or no internet access;
- no NVD API key, so few products are correlated per scan;
- inventoried products have no CPE mapping, or no parseable version.

An empty result is a legitimate outcome: VulScanner will not attach a CVE
without version or KB evidence.

### NVD returns 403

Rate limited. Configure an API key (free, from
<https://nvd.nist.gov/developers/request-an-api-key>). Cached results are reused
for 24 hours, and a stale cache is preferred over losing intelligence entirely.

---

## Reports

### PDF generation fails

PDF output is pure Python (ReportLab) and needs no external binary. If it fails,
reinstall the dependency:

```powershell
.venv\Scripts\python.exe -m pip install --force-reinstall reportlab
```

### "The report file is no longer available"

The file was deleted or moved. Reports are served only from
`VULSCANNER_REPORT_DIR`. Generate it again.

---

## Database

### "database is locked"

SQLite under concurrent scans. VulScanner enables WAL and a busy timeout; for
sustained concurrency use PostgreSQL:

```ini
VULSCANNER_DATABASE_URL=postgresql+psycopg://vulscanner:PASSWORD@localhost:5432/vulscanner
```

then `cd backend; ..\.venv\Scripts\python.exe -m alembic upgrade head`.

### Migration errors after an upgrade

```powershell
cd backend
..\.venv\Scripts\python.exe -m alembic current
..\.venv\Scripts\python.exe -m alembic upgrade head
```

In development, deleting `vulscanner.db` and re-running is also safe — it
contains scan history only.

---

## CLI

### Garbled progress bar or `UnicodeEncodeError`

The console codepage cannot render block characters. VulScanner detects this and
falls back to ASCII; force it with `--no-colour`, or switch the console to UTF-8:

```powershell
chcp 65001
```

### `vulscanner.exe` does not start

Rebuild with `.\scripts\build.ps1`. If a collector is missing at runtime, it
needs adding to the `--hidden-import` list in `build.ps1` — PyInstaller cannot
see imports resolved through the registry.

---

## Collecting diagnostics

```powershell
.\scripts\vulscanner.ps1 version --verbose --json -o diagnostics.json
Get-Content logs\vulscanner.jsonl -Tail 100
.venv\Scripts\python.exe -m pytest backend/tests -q
```

Logs are JSON lines with a redaction filter applied, so they can be shared
without leaking credentials. Review before sending: they contain hostnames,
addresses and configuration detail.
