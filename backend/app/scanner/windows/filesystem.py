"""User-profile filesystem audit.

Metadata only: name, path, size, timestamps, extension, owner, signature status
and (optionally) a hash. File *contents* are never read, stored or transmitted.
"""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import dicts, get, integer, iso, text

DEFAULT_FOLDERS = ["Downloads", "Documents", "Desktop"]

# Extensions that execute or can carry executable payloads.
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".msp", ".cpl", ".sys",
}
SCRIPT_EXTENSIONS = {
    ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
    ".wsh", ".hta", ".lnk", ".reg", ".jar", ".py",
}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".tar", ".gz"}
# Files whose names suggest they hold credentials or keys.
SENSITIVE_NAME_TOKENS = (
    "password", "passwd", "credential", "secret", "private", "id_rsa", "id_ed25519",
    ".pem", ".pfx", ".p12", ".ppk", ".kdbx", "backup_codes", "recovery",
)

SCRIPT = r"""
$folders = __FOLDERS__
$maxFiles = __MAXFILES__
$maxDepth = __MAXDEPTH__
$computeHash = __HASH__
$excludes = __EXCLUDES__

$results = New-Object System.Collections.ArrayList
$truncated = $false
$scanned = @()

foreach ($folder in $folders) {
  $root = Join-Path $env:USERPROFILE $folder
  if (-not (Test-Path -LiteralPath $root)) { continue }
  $scanned += $root
  try {
    $files = Get-ChildItem -LiteralPath $root -File -Recurse -Depth $maxDepth -Force -ErrorAction SilentlyContinue
  } catch { continue }

  foreach ($f in $files) {
    if ($results.Count -ge $maxFiles) { $truncated = $true; break }
    $skip = $false
    foreach ($ex in $excludes) { if ($f.FullName -like $ex) { $skip = $true; break } }
    if ($skip) { continue }

    $owner = $null
    try { $owner = (Get-Acl -LiteralPath $f.FullName -ErrorAction Stop).Owner } catch {}

    $sigStatus = $null; $signer = $null
    if ($f.Extension -match '^\.(exe|dll|ps1|psm1|msi|sys|scr|cab|cat|ocx)$') {
      try {
        $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction Stop
        $sigStatus = [string]$sig.Status
        if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
      } catch {}
    }

    $hash = $null
    if ($computeHash -and $f.Length -lt 100MB -and
        $f.Extension -match '^\.(exe|dll|ps1|bat|cmd|vbs|js|msi|scr|jar)$') {
      try { $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
    }

    # Mark of the Web indicates the file came from an untrusted zone.
    $zone = $null
    try {
      $ads = Get-Content -LiteralPath $f.FullName -Stream Zone.Identifier -ErrorAction Stop
      if ($ads -match 'ZoneId=(\d)') { $zone = [int]$matches[1] }
    } catch {}

    [void]$results.Add([pscustomobject]@{
      Name=$f.Name; Path=$f.FullName; Directory=$f.DirectoryName
      Extension=$f.Extension.ToLower(); Size=$f.Length
      Created=$f.CreationTimeUtc; Modified=$f.LastWriteTimeUtc; Accessed=$f.LastAccessTimeUtc
      Owner=$owner; SignatureStatus=$sigStatus; Signer=$signer; Sha256=$hash
      Hidden=[bool]($f.Attributes -band [IO.FileAttributes]::Hidden)
      ZoneId=$zone
    })
  }
  if ($truncated) { break }
}

[pscustomobject]@{ Files=$results; Truncated=$truncated; ScannedRoots=$scanned }
"""


def _ps_string_array(values: list[str]) -> str:
    escaped = [v.replace("'", "''") for v in values]
    return "@(" + ",".join(f"'{v}'" for v in escaped) + ")" if escaped else "@()"


class FilesystemCollector(BaseCollector):
    name = "filesystem"
    category = "windows"
    description = "Metadata audit of user Downloads, Documents and Desktop folders"
    profiles = ("full",)

    def collect(self, result: CollectorResult) -> None:
        from app.core.config import settings

        folders = list(self.context.option("fs_folders", DEFAULT_FOLDERS))
        max_files = int(self.context.option("fs_max_files", settings.fs_max_files))
        max_depth = int(self.context.option("fs_max_depth", settings.fs_max_depth))
        compute_hash = bool(self.context.option("fs_hash", settings.fs_hash))
        excludes = list(self.context.option("fs_excludes", []))

        script = (
            SCRIPT.replace("__FOLDERS__", _ps_string_array(folders))
            .replace("__MAXFILES__", str(max_files))
            .replace("__MAXDEPTH__", str(max_depth))
            .replace("__HASH__", "$true" if compute_hash else "$false")
            .replace("__EXCLUDES__", _ps_string_array(excludes))
        )

        ps = self.context.runner.run(
            script, depth=4, timeout=max(240, self.context.runner.timeout)
        )
        result.collection_method = self.context.runner.describe_method(
            "Get-ChildItem metadata, Get-Acl owner, Get-AuthenticodeSignature"
            + (" and Get-FileHash (SHA256)" if compute_hash else "")
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "Filesystem audit returned nothing")
            return

        files: list[dict] = []
        for record in dicts(get(ps.data, "Files")):
            extension = text(get(record, "Extension")).lower()
            name_lower = text(get(record, "Name")).lower()
            path = text(get(record, "Path"))
            signature = text(get(record, "SignatureStatus"))
            zone = integer(get(record, "ZoneId"))

            categories = []
            if extension in EXECUTABLE_EXTENSIONS:
                categories.append("executable")
            if extension in SCRIPT_EXTENSIONS:
                categories.append("script")
            if extension in ARCHIVE_EXTENSIONS:
                categories.append("archive")
            if any(token in name_lower for token in SENSITIVE_NAME_TOKENS):
                categories.append("sensitive-name")

            files.append(
                {
                    "name": text(get(record, "Name")),
                    "path": path,
                    "directory": text(get(record, "Directory")),
                    "extension": extension,
                    "size_bytes": integer(get(record, "Size"), 0),
                    "created": iso(get(record, "Created")),
                    "modified": iso(get(record, "Modified")),
                    "accessed": iso(get(record, "Accessed")),
                    "owner": text(get(record, "Owner")),
                    "signature_status": signature or None,
                    "signed": signature == "Valid" if signature else None,
                    "publisher": text(get(record, "Signer")),
                    "sha256": text(get(record, "Sha256")) or None,
                    "hidden": bool(get(record, "Hidden")),
                    "zone_id": zone,
                    "downloaded_from_internet": zone in (3, 4),
                    "categories": categories,
                }
            )

        executables = [f for f in files if "executable" in f["categories"]]
        scripts = [f for f in files if "script" in f["categories"]]
        unsigned_executables = [
            f for f in executables if f["signed"] is False
        ]
        internet_executables = [
            f
            for f in executables + scripts
            if f["downloaded_from_internet"]
        ]
        sensitive = [f for f in files if "sensitive-name" in f["categories"]]

        result.data = {
            "scanned_roots": [text(r) for r in (get(ps.data, "ScannedRoots") or [])],
            "files": files,
            "file_count": len(files),
            "truncated": bool(get(ps.data, "Truncated")),
            "limits": {
                "max_files": max_files,
                "max_depth": max_depth,
                "hashing_enabled": compute_hash,
                "excludes": excludes,
            },
            "total_size_bytes": sum(f["size_bytes"] or 0 for f in files),
            "executables": executables,
            "scripts": scripts,
            "unsigned_executables": unsigned_executables,
            "internet_sourced_executables": internet_executables,
            "sensitive_named_files": [
                {"name": f["name"], "path": f["path"], "modified": f["modified"]}
                for f in sensitive
            ],
            "by_extension": {
                ext: sum(1 for f in files if f["extension"] == ext)
                for ext in sorted({f["extension"] for f in files if f["extension"]})
            },
        }

        if result.data["truncated"]:
            result.warn(
                f"The filesystem audit stopped at the configured limit of {max_files} "
                "files, so coverage of the scanned folders is partial."
            )
