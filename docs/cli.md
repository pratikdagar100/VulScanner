# Command-line reference

```
vulscanner <command> [options]
```

From a source checkout use `.\scripts\vulscanner.ps1` (or `scripts\vulscanner.bat`);
after `.\scripts\build.ps1`, use `dist\vulscanner.exe`.

---

## Global output options

Available on every command.

| Option | Effect |
|---|---|
| `--output`, `-o PATH` | Write output to a file instead of stdout |
| `--json` | Emit JSON |
| `--csv` | Emit CSV |
| `--html` | Emit HTML |
| `--pdf` | Emit PDF |
| `--quiet`, `-q` | Suppress progress and decoration |
| `--verbose`, `-v` | Show per-finding detail and tracebacks on error |
| `--no-colour` | Disable ANSI colour |

`--json` and `--csv` write machine-readable output to stdout so it can be piped;
everything else goes to stderr.

---

## `vulscanner version`

Reports the build, environment and capability.

```powershell
vulscanner version
vulscanner version --json
vulscanner version --verbose      # adds vulnerability intelligence status
```

Shows the Python and platform version, the PowerShell path, whether Windows
collection is available, whether the session is elevated, how many collectors
are registered, and the configured authorized scopes.

---

## `vulscanner scan`

Assess this machine, an authorized host, or an authorized network.

```powershell
vulscanner scan local
vulscanner scan local --profile quick
vulscanner scan local --profile full
vulscanner scan --target 192.168.1.25 --profile standard
vulscanner scan --target server01 --username DOMAIN\admin --ask-password
```

### Options

| Option | Description |
|---|---|
| `TARGET` / `--target`, `-t` | Target IP, hostname or CIDR. `local` means this machine |
| `--profile`, `-p` | `quick`, `standard`, `full`, `network`, `compliance`, `custom` |
| `--name` | Friendly name recorded with the scan |
| `--ports` | Port range for discovery, e.g. `22,80,443,8000-8100` |
| `--discover` | Also sweep the locally attached subnet |
| `--scope CIDR` | Explicit discovery scope |
| `--banner` | Read service banners on open ports |
| `--no-cve` | Skip CVE correlation (offline mode) |
| `--include COLLECTORS` | Comma-separated collectors to add to the profile |
| `--exclude COLLECTORS` | Comma-separated collectors to skip |
| `--username` | Account for an authorized remote (WinRM) assessment |
| `--ask-password` | Prompt for the remote password |
| `--report FORMAT` | Generate a report when the scan finishes |

### Profiles

| Profile | Contents |
|---|---|
| `quick` | OS, patches, software, antivirus/Defender, firewall, UAC, accounts, RDP, adapters, ports, shares |
| `standard` | Full Windows security audit; the default |
| `full` | Everything: Windows Update agent query, filesystem metadata audit, PowerShell history analysis, LLDP/CDP |
| `network` | Network discovery and service assessment; Windows collectors skipped |
| `compliance` | Configuration and policy focused: audit policy, group policy, authentication, boot integrity, logging |
| `custom` | Only the collectors named with `--include` |

List the exact collector set for each profile with `GET /api/scans/profiles`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed, no critical findings |
| 1 | Scan error |
| 2 | Critical findings present |
| 3 | Target not authorized |
| 130 | Interrupted |

Useful in CI:

```powershell
vulscanner scan local --profile standard --quiet
if ($LASTEXITCODE -eq 2) { Write-Error 'Critical findings present'; exit 1 }
```

---

## `vulscanner network`

### `network discover`

```powershell
vulscanner network discover --scope 192.168.1.0/24
vulscanner network discover --scope 10.0.5.0/24 --profile standard --banner
vulscanner network discover --scope 192.168.1.0/24 --json -o hosts.json
```

| Option | Description |
|---|---|
| `--scope`, `-s CIDR` | **Required.** Authorized network scope |
| `--profile` | `safe` (27 common ports) or `standard` (broader sweep) |
| `--ports` | Explicit port list, overriding the profile |
| `--banner` | Read service banners |
| `--no-resolve` | Skip reverse DNS |
| `--max-hosts N` | Safety limit on addresses probed (default 4096) |

Discovery uses full TCP connect handshakes and ordinary reverse DNS. VulScanner
implements **no stealth, fragmentation, decoy or evasion techniques** — an
authorized assessment should be visible to the defenders of the network.

Reported OS values are *inferred* from the observed service mix and always carry
a confidence level. They are not definitive identification.

### `network topology`

```powershell
vulscanner network topology
vulscanner network topology --scan-id 12 --json
```

Prints every topology edge with its confidence and the evidence behind it.
`observed` edges come from the neighbour cache, the routing table or an imported
LLDP/CDP announcement; `inferred` edges are deduced from IP addressing.

### `network hosts`

```powershell
vulscanner network hosts
vulscanner network hosts --scan-id 12
```

---

## `vulscanner findings`

```powershell
vulscanner findings
vulscanner findings --severity critical --detail
vulscanner findings --scan-id 12 --category firewall
vulscanner findings --search "SMB" --json
vulscanner findings --remediation
vulscanner findings --csv -o findings.csv
```

| Option | Description |
|---|---|
| `--scan-id`, `--asset-id` | Restrict to one scan or asset |
| `--severity` | `critical`, `high`, `medium`, `low`, `informational` |
| `--category` | Finding category, e.g. `firewall`, `patch`, `accounts` |
| `--status` | `open`, `resolved`, `reopened`, `risk_accepted`, `false_positive` |
| `--search` | Match text in the title or description |
| `--limit` | Maximum rows (default 100) |
| `--detail` | Full detail per finding: evidence, impact, remediation |
| `--remediation` | Show the ordered remediation plan instead of the list |

---

## `vulscanner report` and `vulscanner reports`

```powershell
vulscanner report                          # latest scan, HTML
vulscanner report --scan-id 12 --pdf
vulscanner report --scan-id 12 --json -o scan12.json
vulscanner report --scan-id 12 --html --open

vulscanner reports list
vulscanner reports scans                   # scans available for reporting
```

Reports carry the scan id, timestamps, target, scanner version, profile and
per-collector evidence timestamps, so any report can be traced to the collection
that produced it.

PDF generation is pure Python (ReportLab) — no external binary or headless
browser is required.

---

## Worked examples

**Full audit of this machine, PDF report**

```powershell
vulscanner scan local --profile full --report pdf
```

**Authorized remote host**

```powershell
vulscanner scan --target 192.168.1.25 --profile standard `
    --username DOMAIN\svc_audit --ask-password
```

**Network discovery with a saved inventory**

```powershell
vulscanner network discover --scope 192.168.1.0/24 --csv -o inventory.csv
```

**Offline assessment (no internet access)**

```powershell
vulscanner scan local --profile full --no-cve
```

**Only the collectors you care about**

```powershell
vulscanner scan local --profile custom --include defender,firewall,rdp,ports
```

**Weekly scheduled audit**

```powershell
$action = New-ScheduledTaskAction -Execute 'C:\VulScanner\dist\vulscanner.exe' `
    -Argument 'scan local --profile full --report html --quiet'
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 3am
Register-ScheduledTask -TaskName 'VulScanner weekly audit' `
    -Action $action -Trigger $trigger -RunLevel Highest
```
