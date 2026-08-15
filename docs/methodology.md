# Assessment methodology

How VulScanner reaches each conclusion, and what it deliberately refuses to
conclude.

---

## The evidence rule

Every finding names the command or registry key that produced it, when it was
read, and how directly it was evidenced. Two consequences follow:

1. **A value that could not be read produces a warning, not a finding.** If
   `auditpol` returns nothing because the session is not elevated, VulScanner
   reports "audit policy could not be read" — it does not report "auditing is
   disabled".
2. **A patch is never called missing without evidence.** "Missing" requires the
   Windows Update agent to have evaluated applicability against this specific
   host and reported the update as not installed.

---

## Confidence levels

| Level | Meaning |
|---|---|
| `confirmed` | Read directly from an authoritative source, unambiguous |
| `high` | Strong evidence, small chance of a benign explanation |
| `medium` | Evidence supports the finding but a legitimate configuration could explain it |
| `low` | Indicative only; needs operator confirmation |
| `informational` | Reported for awareness; not a weakness by itself |

Confidence multiplies into the risk score, so a lower-confidence finding is
ranked below an equivalent confirmed one.

**Worked example.** `Get-LocalUser` reports `PasswordRequired = false` for
accounts linked to a Microsoft account or using Windows Hello, even though a
credential exists. That check therefore ships at `medium` confidence with the
caveat stated in the finding, rather than asserting a passwordless account.

---

## Collection techniques

All collection is read-only, through documented Windows management interfaces.

| Area | Source |
|---|---|
| OS, hardware, BIOS | `Win32_OperatingSystem`, `Win32_ComputerSystem`, `Win32_BIOS`, `CurrentVersion` registry |
| Patches | `Win32_QuickFixEngineering`, Component Based Servicing package keys, `Microsoft.Update.Session` |
| Software | Uninstall registry hives (HKLM 64/32-bit, HKCU), optionally `Get-AppxPackage` |
| Defender | `Get-MpComputerStatus`, `Get-MpPreference`, Windows Defender registry |
| Security products | `root/SecurityCenter2` WMI namespace, `Win32_Service` |
| Firewall | `Get-NetFirewallProfile`, `Get-NetFirewallRule` with port/address/app/service filters |
| Accounts | `Get-LocalUser`, `Get-LocalGroupMember`, `net accounts` |
| Policy | `auditpol /get /category:*`, `secedit /export`, LSA and Policies registry keys |
| RDP | Terminal Server registry keys, `TermService`, firewall group, `Get-NetTCPConnection` |
| Boot integrity | `Confirm-SecureBootUEFI`, `Get-Tpm`, `Win32_DeviceGuard`, `Get-BitLockerVolume` |
| Autoruns | Run/RunOnce keys, Startup folders, auto-start services, logon/boot scheduled tasks, `Get-AuthenticodeSignature` |
| Certificates | `Cert:` PSDrive enumeration — metadata only |
| Network | `Get-NetAdapter`, `Get-NetIPAddress`, `Get-NetRoute`, `Get-NetTCPConnection`, `Get-NetUDPEndpoint`, `Get-SmbShare`, `Get-NetNeighbor`, `Get-DnsClient*` |

Where a modern cmdlet is unavailable, collectors fall back to a documented
alternative (`arp -a`, `netstat -ano`, `Win32_NetworkAdapterConfiguration`) and
record which source was used, since attribution quality differs.

---

## Network discovery

```
expand scope → liveness probe → service sweep → enrich → infer OS
```

- **Liveness** is a TCP connect attempt against a small set of common ports. A
  host that answers on any of them is live. ICMP filtering is normal, so silence
  does not prove absence — the CLI says so explicitly.
- **Service sweep** is a full TCP connect handshake per port. There is no SYN
  scanning, fragmentation, decoy or timing evasion; the assessment is meant to
  be visible.
- **Banner reading** is optional and passive: VulScanner reads what a service
  volunteers on connect (and issues a plain `HEAD /` for HTTP ports). It never
  sends a payload intended to trigger a vulnerability.
- **Enrichment** attaches MAC and vendor from the local neighbour cache, and
  marks the gateway from the routing table.
- **Safety limit**: a scope larger than 4096 addresses is refused unless raised
  explicitly.

### OS inference

Inference is from the observed service mix only, and always carries confidence:

| Observed | Inference | Confidence |
|---|---|---|
| 135 + 139 + 445 | Windows | high |
| 3389 + 445 | Windows | high |
| 5985 | Windows | medium |
| 135 | Windows | low |
| 22 | Linux/Unix | low |
| 9100 + 515 | Network device / printer | medium |

This is a hint for triage, never identification. VulScanner does not fingerprint
TCP/IP stacks.

---

## Topology confidence

| Confidence | Basis |
|---|---|
| `observed` | Neighbour cache entry, routing-table next hop, imported LLDP/CDP announcement |
| `inferred` | Same-subnet membership, assumed internet reachability beyond the gateway |
| `unknown` | Placeholder |

Inferred edges describe **logical reachability**, not verified physical cabling,
and the UI and reports say so wherever the graph is shown.

Windows exposes no LLDP neighbour table and implements no CDP. Rather than
invent switch relationships, VulScanner reports what it can verify — agent and
protocol-binding state — and marks neighbour discovery unavailable. An operator
with an LLDP-aware capture can supply a JSON export, which is ingested and
labelled `observed-external`.

---

## Vulnerability correlation

Two evidence paths, both requiring a concrete link to the asset:

**1. CPE matching (software → CVE)**

```
inventoried product + version
    → mapped to a CPE vendor/product
    → NVD query for that CPE
    → installed version compared against each affected range
    → match only when the version falls inside the range
```

A CVE with no explicit affected range does not produce a match. A product with
no parseable version does not participate at all — it is reported in the
software inventory with a warning instead.

**2. Missing KB (update agent → vulnerability)**

The Windows Update agent's own applicability determination is the evidence, so
these records carry `confirmed` confidence.

**What VulScanner will not do:** report a CVE simply because the host runs
Windows. Correlation requires a matched product version or a KB the agent says
is missing.

Every record stores both the **official CVSS** and the **VulScanner risk score**,
plus the match method, the evidence, and CISA KEV membership.

---

## Risk scoring

```
risk = base × exposure × exploitation × confidence × asset_criticality
       + adjustments
```

| Component | Values |
|---|---|
| base | CVSS × 10, or rule severity (critical 88, high 70, medium 45, low 20) |
| exposure | internet 1.35, network 1.15, adjacent 1.0, local 0.75, none 0.4 |
| exploitation | KEV ×1.30, ransomware ×1.08, public exploit ×1.12, NVD exploitability ±10% |
| confidence | confirmed 1.0, high 0.95, medium 0.8, low 0.6, informational 0.4 |
| asset_criticality | critical 1.25, high 1.12, normal 1.0, low 0.85 |
| adjustments | disabled control +6, missing patch +5, weak config on an exposed service +4 |

A local-only attack vector is capped at the local exposure multiplier, so an
open port cannot inflate a vulnerability that requires local access.

| Score | Severity |
|---|---|
| 90–100 | Critical |
| 70–89 | High |
| 40–69 | Medium |
| 1–39 | Low |
| 0 | Informational |

### Overall security score

```
score = 100 × e^-(0.35·critical + 0.12·high + 0.035·medium + 0.008·low)
```

Exponential decay rather than a linear penalty, so the score degrades smoothly:
one unpatched critical always outranks many low-severity findings, and the score
never flattens to zero and hides further deterioration.

---

## Detection rule catalogue

| Prefix | Area | Examples |
|---|---|---|
| `AV`, `DEF`, `AMSI` | Antimalware | No enabled AV, real-time protection off, tamper protection off, broad exclusions, stale signatures, cloud protection off, dangling AMSI provider |
| `FW` | Firewall | Profile disabled, permissive inbound rule |
| `UAC` | Elevation | UAC disabled, no-prompt elevation, secure desktop off, remote token filtering disabled |
| `ACC` | Accounts | Guest enabled, no password required, weak password policy, no lockout, auto-logon with stored password, excess administrators |
| `RDP` | Remote Desktop | NLA disabled, network exposed, legacy security layer |
| `AUTH` | Authentication | SMBv1, WDigest plaintext, weak NTLM level, SMB signing not required, LSA protection off |
| `BOOT` | Boot integrity | Secure Boot off, OS volume unencrypted, Credential Guard not running |
| `LOG` | Detection capability | Audit subcategory gaps, small Security log, no script block logging, PowerShell v2 present, Sysmon absent |
| `RUN` | Persistence surface | Unsigned autorun in a writable path, stale autorun targets |
| `CERT` | Certificates | Expired or weak certificates in trust stores, expiring certificates with private keys |
| `SEC` | Secret exposure | Credentials in PowerShell history, credential-shaped environment variables, writable PATH entries |
| `PATCH` | Patching | Missing security updates, pending reboot, automatic updates disabled, build past end of servicing |
| `NET`, `NETP`, `RPC`, `SHARE`, `DISC` | Network exposure | High-risk listening port, publicly bound service, sharing on a public network, Remote Registry, Print Spooler, world-readable share, exposed service across the estate |
| `CVE-MATCH` | Vulnerabilities | Correlated CVE with version evidence |

---

## Known limitations

- **Windows collection requires Windows.** On other platforms only network
  assessment runs.
- **Unelevated scans are partial.** Defender preferences, audit policy and the
  local security policy need administrative rights; their absence is reported.
- **Discovery is TCP only.** A host that answers on no probed port is not
  reported, even if it is live.
- **CVE correlation covers mapped products.** Products without a CPE mapping or
  a parseable version are inventoried but not correlated. Coverage is also
  bounded by the NVD rate limit when no API key is configured.
- **Topology is partly inferred.** Without LLDP/CDP, switch-level relationships
  cannot be observed from Windows.
- **PowerShell history is per-user.** Only the scanning user's history is
  analysed; other users' history is not read.
- **Point-in-time.** Findings reflect the target's state at the evidence
  timestamps recorded in the report.
