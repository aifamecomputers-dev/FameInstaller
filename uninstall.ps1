[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("Alpa","Amax")]
  [string]$Org,

  # If true, continue uninstalling other apps even if one fails
  [switch]$ContinueOnError
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BaseRoot  = "C:\ProgramData\FameInstaller"
$LogDir    = Join-Path $BaseRoot "logs"
$StateDir  = Join-Path $BaseRoot "state\$Org"
$StateFile = Join-Path $StateDir "installed.json"
New-Item -ItemType Directory -Force -Path $LogDir, $StateDir | Out-Null

$Stamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogDir "uninstall_$Org`_$Stamp.log"

function Write-Log {
  param([string]$Message, [ValidateSet("INFO","WARN","ERROR","OK")] [string]$Level="INFO")
  $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
  $line | Tee-Object -FilePath $LogFile -Append
}

function Ensure-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Log "Not running as Administrator. Re-launching elevated..." "WARN"
    $args = @("-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"","-Org",$Org)
    if ($ContinueOnError) { $args += "-ContinueOnError" }
    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs | Out-Null
    exit 0
  }
}

function Wait-For-InstallerIdle {
  param([int]$MaxMinutes = 45, [int]$PollSeconds = 10)
  $deadline = (Get-Date).AddMinutes($MaxMinutes)
  while ($true) {
    $msi = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue
    if (-not $msi) { return }
    if (Get-Date -gt $deadline) { throw "Timed out waiting for other installations (msiexec) to finish." }
    Write-Log "Another installation is running (msiexec). Waiting..." "WARN"
    Start-Sleep -Seconds $PollSeconds
  }
}

function Load-State {
  if (-not (Test-Path $StateFile)) {
    throw "State file not found: $StateFile`nRun install.ps1 first on this machine to generate uninstall tracking."
  }
  return (Get-Content $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Normalize-UninstallCommand {
  param([string]$Cmd)

  if (-not $Cmd) { return $null }
  $c = $Cmd.Trim()

  # If it is "MsiExec.exe /I{GUID}" or "/X{GUID}" -> keep, but ensure /X and quiet flags
  if ($c -match '(?i)msiexec(\.exe)?\s+') {
    # ensure it's uninstall and silent
    if ($c -match '(?i)\s/I\s*\{') { $c = ($c -replace '(?i)\s/I\s*', ' /X ') }
    if ($c -notmatch '(?i)\s/X\s*\{') {
      # could be /X{GUID} without spaces; leave as is
    }
    if ($c -notmatch '(?i)/qn') { $c += ' /qn' }
    if ($c -notmatch '(?i)/norestart') { $c += ' /norestart' }
    return $c
  }

  # Non-msiexec uninstallers:
  # Prefer if it already includes silent flags; otherwise we will try a conservative silent add-on
  return $c
}

function Try-UninstallCommand {
  param([string]$Cmd)

  $cmd = Normalize-UninstallCommand -Cmd $Cmd
  if (-not $cmd) { return $false }

  # Split into exe + args (basic parser)
  $exe = $null
  $args = $null

  if ($cmd.StartsWith('"')) {
    $secondQuote = $cmd.IndexOf('"', 1)
    if ($secondQuote -gt 1) {
      $exe = $cmd.Substring(1, $secondQuote - 1)
      $args = $cmd.Substring($secondQuote + 1).Trim()
    }
  } else {
    $parts = $cmd.Split(' ', 2)
    $exe = $parts[0]
    $args = if ($parts.Count -gt 1) { $parts[1] } else { "" }
  }

  if (-not $exe) { return $false }

  # If it's msiexec, run directly
  Wait-For-InstallerIdle
  Write-Log "Uninstall cmd: $exe $args"
  $p = Start-Process -FilePath $exe -ArgumentList $args -Wait -PassThru -ErrorAction Stop
  $code = $p.ExitCode

  if ($code -eq 0 -or $code -eq 3010 -or $code -eq 1605) {
    # 1605 = product not installed
    Write-Log "Uninstall OK (exit=$code)" "OK"
    return $true
  }

  Write-Log "Uninstall command returned exit=$code" "WARN"
  return $false
}

function Uninstall-MsiByProductCode {
  param([string]$ProductCode)
  if (-not $ProductCode) { return $false }
  Wait-For-InstallerIdle
  $args = "/x $ProductCode /qn /norestart"
  Write-Log "MSI uninstall: msiexec.exe $args"
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
  $code = $p.ExitCode
  if ($code -eq 0 -or $code -eq 3010 -or $code -eq 1605) {
    Write-Log "MSI uninstall OK (exit=$code)" "OK"
    return $true
  }
  Write-Log "MSI uninstall failed (exit=$code)" "WARN"
  return $false
}

# ----------------------------
# MAIN
# ----------------------------
try {
  Ensure-Admin
  Write-Log "==== Fame Uninstaller start | Org=$Org | Host=$env:COMPUTERNAME ===="

  $state = Load-State

  # Reverse order uninstall
  $items = @($state.items) | Sort-Object installedAt -Descending

  foreach ($it in $items) {
    $file = [string]$it.file
    $type = [string]$it.type
    Write-Log "Uninstalling item: $file (type=$type)"

    try {
      $done = $false

      # Prefer MSI ProductCode if available
      if ($type -eq "msi" -and $it.msiProductCode) {
        $done = Uninstall-MsiByProductCode -ProductCode $it.msiProductCode
      }

      # For EXE (and MSI fallback), try stored uninstall entries
      if (-not $done -and $it.uninstallEntries) {
        # Prefer QuietUninstallString first
        $entries = @($it.uninstallEntries)
        foreach ($e in $entries) {
          if ($e.QuietUninstallString) {
            if (Try-UninstallCommand -Cmd $e.QuietUninstallString) { $done = $true; break }
          }
        }
        if (-not $done) {
          foreach ($e in $entries) {
            if ($e.UninstallString) {
              if (Try-UninstallCommand -Cmd $e.UninstallString) { $done = $true; break }
            }
          }
        }
      }

      # If still not done and MSI, try registry uninstall by product code presence in uninstall strings
      if (-not $done -and $type -eq "msi" -and $it.msiProductCode) {
        $done = Uninstall-MsiByProductCode -ProductCode $it.msiProductCode
      }

      if (-not $done) {
        throw "No working uninstall method recorded for $file. (Vendor may not register uninstall info.)"
      }
    }
    catch {
      Write-Log "FAILED uninstall: $file :: $($_.Exception.Message)" "ERROR"
      if (-not $ContinueOnError) { throw }
    }
  }

  Write-Log "==== Uninstall completed. Log: $LogFile ====" "OK"
  exit 0
}
catch {
  Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
  Write-Log "Log file: $LogFile" "ERROR"
  exit 1
}
