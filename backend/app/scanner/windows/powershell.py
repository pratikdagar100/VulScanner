"""PowerShell engine versions, logging configuration and language mode."""

from __future__ import annotations

from app.scanner.base import BaseCollector, CollectorResult
from app.scanner.util import as_list, boolean, get, integer, text

SCRIPT = r"""
$engines = @()
try {
  $engines = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PowerShell' -ErrorAction Stop |
    ForEach-Object {
      $id = $_.PSChildName
      $inst = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Install
      $ver  = $null
      try {
        $ver = (Get-ItemProperty "$($_.PSPath)\PowerShellEngine" -ErrorAction Stop).PowerShellVersion
      } catch {}
      [pscustomobject]@{ Id=$id; Installed=($inst -eq 1); Version=$ver }
    }
} catch {}

function Get-PolicyValue($path, $name) {
  try { return (Get-ItemProperty $path -ErrorAction Stop).$name } catch { return $null }
}

$mlBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$sbBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
$trBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'

[pscustomobject]@{
  Engines             = $engines
  CurrentVersion      = $PSVersionTable.PSVersion.ToString()
  CurrentEdition      = $PSVersionTable.PSEdition
  LanguageMode        = $ExecutionContext.SessionState.LanguageMode.ToString()
  ExecutionPolicyMachine = (Get-ExecutionPolicy -Scope LocalMachine).ToString()
  ExecutionPolicyUser    = (Get-ExecutionPolicy -Scope CurrentUser).ToString()
  ExecutionPolicyEffective = (Get-ExecutionPolicy).ToString()
  ModuleLogging       = Get-PolicyValue $mlBase 'EnableModuleLogging'
  ScriptBlockLogging  = Get-PolicyValue $sbBase 'EnableScriptBlockLogging'
  ScriptBlockInvocationLogging = Get-PolicyValue $sbBase 'EnableScriptBlockInvocationLogging'
  Transcription       = Get-PolicyValue $trBase 'EnableTranscripting'
  TranscriptionPath   = Get-PolicyValue $trBase 'OutputDirectory'
  ConstrainedLanguagePolicy = $env:__PSLockdownPolicy
}
"""


class PowerShellCollector(BaseCollector):
    name = "powershell"
    category = "windows"
    description = "PowerShell engines, execution policy and logging configuration"
    profiles = ("standard", "full", "compliance")

    def collect(self, result: CollectorResult) -> None:
        ps = self.context.runner.run(SCRIPT, depth=4)
        result.collection_method = self.context.runner.describe_method(
            "PSVersionTable, Get-ExecutionPolicy and PowerShell policy registry keys"
        )
        if not ps.ok or not isinstance(ps.data, dict):
            result.fail(ps.friendly_error() or "No PowerShell information returned")
            return

        raw = ps.data
        engines = []
        v2_present = False
        for record in as_list(get(raw, "Engines")):
            if not isinstance(record, dict):
                continue
            engine_id = text(get(record, "Id"))
            version = text(get(record, "Version"))
            installed = bool(get(record, "Installed"))
            engines.append(
                {"id": engine_id, "version": version, "installed": installed}
            )
            if installed and (engine_id == "1" or version.startswith("2.")):
                v2_present = True

        result.data = {
            "engines": engines,
            "current_version": text(get(raw, "CurrentVersion")),
            "current_edition": text(get(raw, "CurrentEdition")),
            "language_mode": text(get(raw, "LanguageMode")),
            "execution_policy": {
                "effective": text(get(raw, "ExecutionPolicyEffective")),
                "machine": text(get(raw, "ExecutionPolicyMachine")),
                "user": text(get(raw, "ExecutionPolicyUser")),
            },
            "logging": {
                "module_logging": boolean(get(raw, "ModuleLogging"), False),
                "script_block_logging": boolean(get(raw, "ScriptBlockLogging"), False),
                "script_block_invocation_logging": boolean(
                    get(raw, "ScriptBlockInvocationLogging"), False
                ),
                "transcription": boolean(get(raw, "Transcription"), False),
                "transcription_path": text(get(raw, "TranscriptionPath")),
            },
            "powershell_v2_engine_present": v2_present,
            "lockdown_policy": integer(get(raw, "ConstrainedLanguagePolicy")),
        }
