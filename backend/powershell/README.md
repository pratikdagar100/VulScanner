# VulScanner PowerShell library

Read-only PowerShell used by the VulScanner collectors.

Most collectors embed their query directly in the Python module so the script
and the parser that consumes it stay together and cannot drift apart. This
directory holds the standalone scripts that are useful to run by hand — for
verifying a finding, or for collecting from a host that cannot run VulScanner
itself.

Every script here:

* is **read-only** — it reads state and changes nothing;
* emits a single JSON object on stdout, so its output can be piped into
  `ConvertFrom-Json` or stored as evidence;
* never reads passwords, password hashes or private key material.

Run one with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\security\Get-SecurityPosture.ps1
```

`PowerShellRunner.run_script_file()` executes these through the same path the
embedded queries use, and refuses any path that escapes this directory.

| Directory  | Contents                                            |
|------------|-----------------------------------------------------|
| `system/`  | OS, hardware, patch and software inventory           |
| `security/`| Defender, firewall, accounts, policy and boot state  |
| `network/` | Adapters, listening ports, shares and neighbours     |
