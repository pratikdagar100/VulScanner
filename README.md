# VulScanner

**Agent-less Windows vulnerability, security posture and network assessment platform.**

VulScanner answers one question, with evidence:

> *Is my Windows system or authorized network secure, what vulnerabilities and
> misconfigurations exist, how serious are they, and what should I do about them?*

It runs against the machine you are on, an authorized remote Windows host, or an
authorized network range — with no permanent agent installed anywhere. The same
scanning engine drives a command-line tool, a REST API and a web dashboard.

```powershell
vulscanner scan local --profile full
```

---

## What it does

| Capability | How |
|---|---|
| Windows security audit | 24 collectors over PowerShell, CIM/WMI and the registry |
| Patch assessment | Installed hotfixes plus updates the Windows Update agent reports as applicable and missing |
| Software inventory | Uninstall registry hives, feeding CVE correlation |
| Network assessment | Adapters, listening ports with process attribution, shares, ARP, DNS, RPC |
| Network discovery | TCP connect sweep of an authorized scope, with service and OS inference |
| Network topology | Interactive map that separates *observed* links from *inferred* ones |
| Vulnerability intelligence | NVD CPE correlation and the CISA KEV catalogue |
| Risk scoring | A VulScanner risk score, always shown separately from the official CVSS |
| Remediation | Ordered plan with what/why/fix/verify per finding — never executed automatically |
| Reporting | HTML, PDF, JSON and CSV, all carrying full provenance |

---

## Screens

| | |
|---|---|
| **Dashboard** | Security score, severity breakdown, category distribution, score trend, top risky assets, most exposed services |
| **Findings** | Every finding with evidence, detection method, confidence and a risk-score breakdown |
| **Network map** | Zoomable topology with risk, OS and port filters |
| **Remediation** | Priority-ordered plan with SLA, effort and verification steps |
| **Posture views** | Software, Patches, Firewall, Defender, RDP, Users & Groups, Security Policies |

---

## Quick start

### Windows (full platform)

```powershell
git clone https://github.com/pratikdagar100/VulScanner.git
cd VulScanner
.\scripts\install.ps1      # verifies Python/Node, installs deps, creates .env, migrates
.\scripts\start.ps1        # API on :8000, web app on :5173
```

The bootstrap administrator password is printed **once**, in the API console, on
first start. Store it immediately, then change it under Settings.

### CLI only

```powershell
.\scripts\install.ps1 -SkipFrontend
.\scripts\vulscanner.ps1 scan local --profile full
```

### Build `vulscanner.exe`

```powershell
.\scripts\build.ps1        # PyInstaller one-file executable in dist\
.\dist\vulscanner.exe scan local
```

---

## Command line

```powershell
vulscanner --help

vulscanner version                                       # capability report
vulscanner scan local                                    # standard audit of this machine
vulscanner scan local --profile quick                    # fast posture check
vulscanner scan local --profile full                     # everything, including the update agent
vulscanner scan --target 192.168.1.25 --profile standard --username admin --ask-password
vulscanner network discover --scope 192.168.1.0/24
vulscanner network topology
vulscanner findings --severity high --detail
vulscanner findings --remediation
vulscanner report --scan-id 12 --pdf
vulscanner reports list
```

Output options: `--json`, `--csv`, `--html`, `--pdf`, `--output <path>`,
`--quiet`, `--verbose`.

Exit codes: `0` clean, `2` critical findings present, `3` target not authorized,
`1` scan error — so CI can gate on the result.

---

## REST API

Interactive documentation at `/api/docs` (Swagger) and `/api/redoc`.

```
POST   /api/auth/login              GET    /api/findings
POST   /api/scans                   GET    /api/findings/{id}
GET    /api/scans                   PATCH  /api/findings/{id}
GET    /api/scans/{id}              GET    /api/findings/remediation
POST   /api/scans/{id}/cancel       GET    /api/vulnerabilities
GET    /api/scans/{id}/stream       GET    /api/patches
WS     /api/scans/{id}/ws           GET    /api/network/topology
GET    /api/assets                  GET    /api/network/ports
GET    /api/assets/{id}             POST   /api/reports
GET    /api/dashboard               GET    /api/reports/{id}/download
GET    /api/audit                   POST   /api/targets
```

Live scan progress is available over both Server-Sent Events (`/stream`) and
WebSocket (`/ws`), with a REST snapshot (`/progress`) as a polling fallback.

---

## Authorization boundary

VulScanner refuses to scan anything outside the operator's declared scope.

```
VULSCANNER_AUTHORIZED_SCOPES=127.0.0.0/8,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12
```

A target outside those scopes is rejected before any packet is sent, and the
refusal is written to the audit log. Additional targets are registered through
`POST /api/targets` with an explicit authorization attestation recording who
granted permission.

---

## What VulScanner will not do

By design, and without exception:

- no exploitation — discovered vulnerabilities are never triggered
- no password, hash, token or private-key collection
- no credential dumping, token theft or authentication bypass
- no persistence, stealth, evasion or fragmentation
- no disabling or reconfiguring of security software
- no destructive scanning, and no automatic remediation

Credentials found in PowerShell history or environment variables are **redacted
at the point of detection** — VulScanner reports that a secret is exposed and
where, never the secret itself.

---

## Risk scoring

Two numbers, always shown separately:

- **Official CVSS** — the vendor-published base score for a CVE, unmodified.
- **VulScanner risk score (0–100)** — this weakness, on *this* asset:

```
score = base × exposure × exploitation × confidence × asset_criticality + adjustments
```

Inputs: CVSS or rule severity, network exposure, CISA KEV membership, NVD
exploitability sub-score, attack vector, patch availability, detection
confidence and asset criticality. Every finding ships with the full factor
breakdown, so any score can be traced back to its inputs.

| Score | Severity |
|---|---|
| 90–100 | Critical |
| 70–89 | High |
| 40–69 | Medium |
| 1–39 | Low |
| 0 | Informational |

---

## Evidence, not assumptions

Every finding records the exact command or registry key it came from, a
timestamp, and a confidence level. Two rules follow from that:

1. **A collector that cannot read a value reports a warning** — it never assumes
   the insecure case. Absent evidence produces no finding.
2. **A patch is never called missing without evidence.** "Missing" requires the
   Windows Update agent to report the update as applicable and not installed.

Topology follows the same rule: links evidenced by the neighbour cache, routing
table or an imported LLDP/CDP announcement are marked `observed`; links deduced
from IP addressing are marked `inferred` and described as logical reachability,
never as physical cabling.

---

## Architecture

```
        Web app (React/TS)          CLI (vulscanner.exe)
                 \                        /
                  \                      /
                   REST API (FastAPI) ──┘
                           │
                    Scan orchestrator
                           │
        ┌──────────────────┼──────────────────┐
   Windows scanner   Network scanner    CVE/patch intelligence
        └──────────────────┼──────────────────┘
                     Risk engine
                           │
        ┌──────────────────┼──────────────────┐
     Findings         Network map        Remediation
        └──────────────────┼──────────────────┘
                     Report engine
                  HTML · PDF · JSON · CSV
```

The scanning engine has no dependency on any user interface. The CLI and the API
call the same services, so a scan produces identical data either way.

**Stack:** Python 3.11+, FastAPI, SQLAlchemy 2, Alembic, SQLite (dev) /
PostgreSQL (prod), ReportLab, Jinja2 · React 18, TypeScript, Vite, Tailwind,
Recharts, React Flow.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Component design, data flow, extension points |
| [docs/installation.md](docs/installation.md) | Install, configure, remote scanning prerequisites |
| [docs/cli.md](docs/cli.md) | Full command reference |
| [docs/api.md](docs/api.md) | REST endpoints, authentication, streaming |
| [docs/security.md](docs/security.md) | Security boundaries, RBAC, data handling |
| [docs/methodology.md](docs/methodology.md) | How each check works, risk model, confidence levels |
| [docs/deployment.md](docs/deployment.md) | Hosting the interface, and what must never be published |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common problems and their causes |

---

## Testing

```powershell
.venv\Scripts\python.exe -m pytest backend/tests -q
```

180 tests cover collector parsing, the risk engine, detection rules, CVE
correlation, patch logic, report generation, the API, authentication, RBAC, the
authorization boundary, topology confidence and the CLI.

Tests use a labelled mock provider (`backend/tests/mock_data.py`) so the suite
runs on any platform without needing a vulnerable machine. **The application
never loads that data** — no result shown to an operator is ever synthetic.

---

## Requirements

| | |
|---|---|
| Target OS | Windows 10, Windows 11, current supported builds |
| Python | 3.11 or newer |
| Node.js | 18 or newer (web application only) |
| Privileges | Administrator recommended — without it, Defender preferences, audit policy and the local security policy are reported as incomplete |
| Remote scanning | WinRM enabled on the target; account in Administrators or Remote Management Users |

---

## Licence

MIT — see [LICENSE](LICENSE).

**Use responsibly.** VulScanner is built for authorized defensive security
assessment and blue-team operations. Scan only systems and networks you own or
have written permission to assess.
