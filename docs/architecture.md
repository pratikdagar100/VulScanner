# VulScanner architecture

## Design principles

1. **The engine is independent of any interface.** The CLI, the REST API and the
   web application all drive the same `ScanEngine`. A scan started from the CLI
   is indistinguishable from one started in the browser.
2. **Every result traces back to evidence.** A finding records the command or
   registry key that produced it, when it was read, and how confident the
   detection is.
3. **A failing collector never fails the scan.** Collectors return a structured
   result; the engine records failures and continues.
4. **Absent evidence produces no finding.** A value that could not be read is a
   warning, not an assumption of insecurity.

---

## Layers

```
┌───────────────────────────────────────────────────────────────┐
│  Presentation                                                 │
│    frontend/  React + TypeScript + Vite + Tailwind            │
│    cli/       argparse CLI, ANSI renderer, no dependencies    │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│  API            backend/app/api/                              │
│    auth · scans · assets · findings · vulnerabilities ·       │
│    network · reports · dashboard · audit                      │
│    RBAC, rate limiting, SSE and WebSocket progress            │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│  Services       backend/app/services/                         │
│    scan_service     orchestration and persistence             │
│    analyzers/       detection rules                           │
│    risk_engine      VulScanner risk score                     │
│    cve_service      NVD + CISA KEV                            │
│    patch_service    patch posture and evidence quality        │
│    remediation_service   ordered fix plan                     │
│    report_service   HTML / PDF / JSON / CSV                   │
│    audit_service    append-only audit trail                   │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│  Scanner        backend/app/scanner/                          │
│    engine.py    stage sequencing, progress, cancellation      │
│    runner.py    PowerShell execution (local and WinRM)        │
│    windows/     24 Windows collectors                         │
│    network/     11 network collectors + discovery + topology  │
└───────────────────────────┬───────────────────────────────────┘
                            │
┌───────────────────────────▼───────────────────────────────────┐
│  Persistence    backend/app/models/ + migrations/             │
│    SQLAlchemy 2 · Alembic · SQLite (dev) / PostgreSQL (prod)  │
└───────────────────────────────────────────────────────────────┘
```

---

## Scan lifecycle

```
create_scan()          authorize the target, persist a queued Scan row
     │                 (refused targets are audited and never probed)
     ▼
ScanEngine.run()
     │
     ├── preflight     locate PowerShell, detect elevation, warn on gaps
     ├── collection    run the profile's collectors, one CollectorResult each
     ├── discovery     TCP connect sweep of the scope (when requested)
     ├── topology      build the graph, label each edge observed or inferred
     ▼
persist_results()
     ├── upsert the Asset
     ├── store every CollectorResult as evidence
     ├── run the detection rules      -> findings
     ├── correlate CVEs and patches   -> vulnerabilities
     ├── score everything             -> risk scores
     └── roll up counters and the security score
```

Progress is published to a `ProgressBroker` at every stage, which fans out to
SSE and WebSocket subscribers and is persisted so a page refresh still shows the
correct state.

---

## Collector contract

Every collector subclasses `BaseCollector` and returns a `CollectorResult`:

```python
{
    "status": "success" | "partial" | "failed" | "skipped",
    "data": {...},              # normalized, parser-stable structure
    "warnings": [...],          # what could not be read, and why
    "errors": [...],
    "collection_method": "PowerShell (local): Get-MpComputerStatus",
    "collected_at": "2026-01-15T10:30:00+00:00",
    "duration_seconds": 1.42,
}
```

`BaseCollector.run()` catches everything a collector can raise — including
`PermissionError` and timeouts — so a collector can never abort a scan.

### Adding a collector

1. Create `backend/app/scanner/windows/my_check.py` with a `BaseCollector`
   subclass: set `name`, `category`, `description`, `profiles`, and implement
   `collect(result)`.
2. Register it in `backend/app/scanner/registry.py`.
3. Add detection rules in `backend/app/services/analyzers/` using the
   `@analyzer` decorator.
4. Add mock data to `backend/tests/mock_data.py` and assert the rule fires.

---

## Execution layer

`PowerShellRunner` is the single path to the target:

- scripts are passed as base64 `-EncodedCommand`, so quoting can never break;
- output is framed by markers and forced through `ConvertTo-Json`;
- remote execution wraps the script in `Invoke-Command -ComputerName`;
- **a remote password is handed to the child process through its environment
  block only** — never on a command line, where it would be visible in the
  process list.

The API cannot pass an arbitrary string to the runner: scripts come from
VulScanner's own collector modules or the bundled `backend/powershell` library,
and `run_script_file()` refuses any path that escapes that directory.

---

## Risk engine

```
score = base × exposure × exploitation × confidence × asset_criticality
        + adjustments
```

| Factor | Source |
|---|---|
| base | CVSS × 10, or the detection rule's severity |
| exposure | socket binding, firewall reachability, attack vector |
| exploitation | CISA KEV, ransomware use, NVD exploitability sub-score |
| confidence | how directly the finding was evidenced |
| asset_criticality | operator-assigned asset importance |
| adjustments | disabled control (+6), missing patch (+5), weak config on an exposed service (+4) |

A local-only attack vector is never inflated by network exposure. The full
factor breakdown is stored with each finding and rendered in the UI and reports.

---

## Data model

| Table | Purpose |
|---|---|
| `users`, `roles` | Authentication and RBAC |
| `targets` | Authorized scan targets with attestation |
| `assets` | Discovered hosts and their roll-up counters |
| `scans`, `scan_results` | Scan runs and per-collector evidence |
| `findings` | Detections with evidence, risk factors and triage state |
| `vulnerabilities`, `cves` | Per-asset CVE instances and cached intelligence |
| `patches` | Installed and missing updates with evidence quality |
| `network_hosts`, `network_ports`, `network_connections`, `network_edges` | Network state and topology |
| `reports` | Generated report artefacts |
| `audit_logs` | Append-only activity trail |

`scan_results` is the evidence store: every finding points back at the collector
result that produced it, so any conclusion can be re-derived from raw data.

---

## Concurrency

- Scans run on a bounded `ThreadPoolExecutor` (`VULSCANNER_MAX_CONCURRENT_SCANS`).
- Discovery uses its own thread pools for host probing and port sweeping.
- Cancellation is cooperative: `ScanContext.cancel()` sets an event that the
  engine and discovery loops check between units of work.
- SQLite is opened with WAL and a busy timeout so scan writes and API reads do
  not block each other.
