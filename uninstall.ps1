<# 
FameInstaller - uninstall.ps1 (Uninstallation Script)
- Uninstalls all packages previously installed by install_v1.ps1 / install_v2.ps1
- Reads from C:\ProgramData\FameInstaller\state\<Org>\installed.json
- Safely handles MSI and EXE uninstallations
- Reverses installation order (installed last, uninstalled first)
- Tracks uninstall history in JSON
- Single-run lock to prevent parallel runs
- Auto-elevates to Administrator if needed
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("Alpa","Amax")]
  [string]$Org,

  [switch]$ContinueOnError,
  [switch]$DryRun,

  # Internal flag used by resume task
  [switch]$Resumed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ----------------------------
# Globals / Paths / Logging / State / Lock
# ----------------------------
$script:RebootRequired = $false

$BaseRoot = "C:\ProgramData\FameInstaller"
$LogDir   = Join-Path $BaseRoot "logs"
$StateDir = Join-Path $BaseRoot ("state\{0}" -f $Org)

New-Item -ItemType Directory -Force -Path $LogDir, $StateDir | Out-Null

$Stamp         = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile       = Join-Path $LogDir ("uninstall_{0}_{1}.log" -f $Org, $Stamp)
$StateFile     = Join-Path $StateDir "installed.json"
$UninstallFile = Join-Path $StateDir "uninstalled.json"
$LockFile      = Join-Path $StateDir "uninstall.lock"

# -------- Logging --------
function Write-Log {
  param(
    [Parameter(Mandatory=$true)][string]$Message,
    [ValidateSet("INFO","WARN","ERROR","OK")] [string]$Level="INFO"
  )
  $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
  $line | Tee-Object -FilePath $LogFile -Append | Out-Null
}

# -------- Admin elevation --------
function Ensure-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Log "Not running as Administrator. Re-launching elevated..." "WARN"

    $args = @("-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"","-Org",$Org)
    if ($ContinueOnError) { $args += "-ContinueOnError" }
    if ($DryRun)          { $args += "-DryRun" }
    if ($Resumed)         { $args += "-Resumed" }

    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs | Out-Null
    exit 0
  }
}

# -------- Locking (prevents parallel runs) --------
function Acquire-Lock {
  $staleHours = 2

  if (Test-Path $LockFile) {
    $pidAlive = $false
    $lockAgeOk = $true

    try {
      $age = (Get-Item $LockFile -ErrorAction Stop).LastWriteTime
      if ($age -lt (Get-Date).AddHours(-$staleHours)) { $lockAgeOk = $false }
    } catch {
      $lockAgeOk = $false
    }

    $lock = $null
    try {
      $raw = Get-Content $LockFile -Raw -ErrorAction SilentlyContinue
      if ($raw) { $lock = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue }
    } catch { $lock = $null }

    if ($lock -and $lock.pid) {
      try {
        $pidAlive = @(Get-Process -Id ([int]$lock.pid) -ErrorAction SilentlyContinue).Count -gt 0
      } catch { $pidAlive = $false }
    }

    if ($pidAlive -and $lockAgeOk) {
      throw "Another FameUninstaller run seems active (PID=$($lock.pid)). Lock: $LockFile"
    }

    Write-Log "Clearing stale lock (pidAlive=$pidAlive, lockAgeOk=$lockAgeOk): $LockFile" "WARN"
    Remove-Item $LockFile -Force -ErrorAction SilentlyContinue | Out-Null
  }

  $obj = [pscustomobject]@{
    computer = $env:COMPUTERNAME
    pid      = $PID
    created  = (Get-Date).ToString("o")
  }
  $obj | ConvertTo-Json | Set-Content -Path $LockFile -Encoding UTF8
}

function Release-Lock {
  try {
    if (Test-Path $LockFile) { Remove-Item $LockFile -Force -ErrorAction SilentlyContinue | Out-Null }
  } catch {}
}

# -------- Installer busy wait --------
function Wait-For-InstallerIdle {
  param([int]$MaxMinutes = 45, [int]$PollSeconds = 10)

  $deadline = (Get-Date).AddMinutes($MaxMinutes)

  while ($true) {
    $msi = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue
    if (-not $msi) { return }

    if ((Get-Date) -gt $deadline) {
      throw "Timed out waiting for other installations (msiexec) to finish."
    }

    Write-Log "Another operation is running (msiexec). Waiting..." "WARN"
    Start-Sleep -Seconds $PollSeconds
  }
}

# ----------------------------
# State handling (StrictMode-safe)
# ----------------------------
function Load-InstallState {
  if (Test-Path $StateFile) {
    try {
      $s = Get-Content $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json
      if (-not $s) { throw "Empty state" }
      if ($s.PSObject.Properties.Match("items").Count -eq 0) {
        $s | Add-Member -NotePropertyName "items" -NotePropertyValue @() -Force | Out-Null
      }
      return $s
    } catch {
      Write-Log "Could not load install state: $($_.Exception.Message)" "WARN"
      return $null
    }
  }

  Write-Log "No installation state file found: $StateFile" "WARN"
  return $null
}

function Load-UninstallState {
  if (Test-Path $UninstallFile) {
    try {
      $s = Get-Content $UninstallFile -Raw -Encoding UTF8 | ConvertFrom-Json
      if (-not $s) { throw "Empty state" }
      if ($s.PSObject.Properties.Match("items").Count -eq 0) {
        $s | Add-Member -NotePropertyName "items" -NotePropertyValue @() -Force | Out-Null
      }
      return $s
    } catch { }
  }

  return [pscustomobject]@{
    org       = $Org
    created   = (Get-Date).ToString("o")
    resumed   = [bool]$Resumed
    status    = "running"
    items     = @()
  }
}

function Save-State($state, $file) {
  $state | ConvertTo-Json -Depth 20 | Set-Content -Path $file -Encoding UTF8
}

function Set-StateProp {
  param(
    [Parameter(Mandatory=$true)]$State,
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)]$Value
  )
  if ($State.PSObject.Properties.Match($Name).Count -eq 0) {
    $State | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force | Out-Null
  } else {
    $State.$Name = $Value
  }
}

# ----------------------------
# Uninstall executors
# ----------------------------
function Invoke-QuietUninstall {
  param(
    [Parameter(Mandatory=$true)][string]$UninstallString,
    [int]$Retries = 2
  )

  Wait-For-InstallerIdle

  Write-Log "Executing quiet uninstall: $UninstallString"
  if ($DryRun) { Write-Log "DryRun: skipping execution" "WARN"; return 0 }

  for ($i=1; $i -le $Retries; $i++) {
    try {
      # Handle MSI GUIDs wrapped in curly braces
      if ($UninstallString -match 'msiexec.*\{[A-F0-9\-]+\}') {
        # It's an MSI uninstall via GUID
        $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $UninstallString.Replace('msiexec.exe','').Trim() -Wait -PassThru
      } else {
        # Generic uninstall command
        $p = Invoke-Expression -Command "& $UninstallString" -Wait -PassThru
      }

      $code = [int]$p.ExitCode

      if ($code -eq 0) { return 0 }
      if ($code -eq 3010 -or $code -eq 1641) { $script:RebootRequired = $true; return $code }
      if ($code -eq 1618) { 
        Write-Log "Exit 1618 (another uninstall in progress). Waiting/retrying ($i/$Retries)..." "WARN"
        Wait-For-InstallerIdle
        Start-Sleep -Seconds (5 * $i)
        continue
      }
      
      Write-Log "Uninstall returned exit code: $code" "WARN"
      return $code
    } catch {
      Write-Log "Uninstall error: $($_.Exception.Message)" "WARN"
      if ($i -eq $Retries) { throw }
      Start-Sleep -Seconds (3 * $i)
    }
  }

  return 1618
}

function Invoke-MsiUninstall {
  param(
    [Parameter(Mandatory=$true)][string]$ProductCode,
    [int]$Retries = 2
  )

  Wait-For-InstallerIdle

  $args = "/x `"$ProductCode`" /qn /norestart"
  Write-Log "MSI uninstall: msiexec.exe $args"
  if ($DryRun) { Write-Log "DryRun: skipping execution" "WARN"; return 0 }

  for ($i=1; $i -le $Retries; $i++) {
    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
    $code = [int]$p.ExitCode

    if ($code -eq 0) { return 0 }
    if ($code -eq 3010 -or $code -eq 1641) { $script:RebootRequired = $true; return $code }
    if ($code -eq 1618) {
      Write-Log "MSI exit 1618 (another uninstall in progress). Waiting/retrying ($i/$Retries)..." "WARN"
      Wait-For-InstallerIdle
      Start-Sleep -Seconds (5 * $i)
      continue
    }
    return $code
  }

  return 1618
}

# ----------------------------
# MAIN
# ----------------------------
try {
  Ensure-Admin
  Acquire-Lock

  Write-Log ("==== Fame Folder Uninstaller start | Org={0} | Host={1} | Resumed={2} | DryRun={3} ====" -f $Org, $env:COMPUTERNAME, ([bool]$Resumed), ([bool]$DryRun))

  $installState = Load-InstallState
  if (-not $installState) {
    throw "No installation state found. Nothing to uninstall."
  }

  $uninstallState = Load-UninstallState

  # Get installed items in reverse order (last installed, first uninstalled)
  $items = @($installState.items)
  if ($items.Count -eq 0) {
    throw "No installed items in state file."
  }

  Write-Log ("Found {0} installed items to uninstall" -f $items.Count)
  
  # Reverse array to uninstall in reverse order
  [array]::Reverse($items)

  $uninstalledCount = 0
  $failedCount = 0

  foreach ($item in $items) {
    try {
      $displayName = if ($item.uninstallEntries -and $item.uninstallEntries.Count -gt 0) {
        $item.uninstallEntries[0].DisplayName
      } else {
        $item.file
      }

      Write-Log "Processing: $displayName ($($item.type))"

      $exit = 0

      # If there are uninstall registry entries, use those
      if ($item.uninstallEntries -and $item.uninstallEntries.Count -gt 0) {
        foreach ($entry in $item.uninstallEntries) {
          try {
            if ($entry.WindowsInstaller -eq 1 -and $entry.msiProductCode) {
              # MSI uninstall
              Write-Log "MSI ProductCode: $($entry.msiProductCode)" "INFO"
              $exit = Invoke-MsiUninstall -ProductCode $entry.msiProductCode
            } elseif ($entry.QuietUninstallString) {
              # Use QuietUninstallString if available
              Write-Log "QuietUninstallString: $($entry.QuietUninstallString)" "INFO"
              $exit = Invoke-QuietUninstall -UninstallString $entry.QuietUninstallString
            } elseif ($entry.UninstallString) {
              # Fallback to UninstallString
              Write-Log "UninstallString: $($entry.UninstallString)" "INFO"
              $exit = Invoke-QuietUninstall -UninstallString $entry.UninstallString
            } else {
              throw "No uninstall method available for $($entry.DisplayName)"
            }

            if ($exit -eq 0 -or $exit -eq 1605) {
              Write-Log "Uninstalled OK: $($entry.DisplayName)" "OK"
              $uninstalledCount++
            } elseif ($exit -eq 3010 -or $exit -eq 1641) {
              Write-Log "Uninstall OK (reboot required): $($entry.DisplayName)" "WARN"
              $uninstalledCount++
            } else {
              throw "Uninstaller returned exit code $exit"
            }
          } catch {
            Write-Log "FAILED to uninstall $($entry.DisplayName): $($_.Exception.Message)" "ERROR"
            $failedCount++
            if (-not $ContinueOnError) { throw }
          }
        }
      } else {
        Write-Log "No uninstall entries found for: $displayName (may have been already uninstalled)" "WARN"
      }

      # Record in uninstall state
      $record = [pscustomobject]@{
        file             = $item.file
        displayName      = $displayName
        type             = $item.type
        uninstalledAt    = (Get-Date).ToString("o")
        exitCode         = $exit
        status           = if ($exit -eq 0 -or $exit -eq 1605 -or $exit -eq 3010 -or $exit -eq 1641) { "success" } else { "failed" }
      }

      $uninstallItems = @()
      if ($uninstallState.PSObject.Properties.Match("items").Count -gt 0) { $uninstallItems = @($uninstallState.items) }
      $uninstallItems += $record
      Set-StateProp -State $uninstallState -Name "items" -Value $uninstallItems
      Set-StateProp -State $uninstallState -Name "lastUpdate" -Value (Get-Date).ToString("o")
      Save-State $uninstallState $UninstallFile

    } catch {
      Write-Log "FAILED: $($item.file) :: $($_.Exception.Message)" "ERROR"
      $failedCount++
      if (-not $ContinueOnError) { throw }
    }
  }

  if ($script:RebootRequired -and -not $DryRun) {
    Write-Log "Reboot required detected. System will reboot in 60 seconds..." "WARN"
    Set-StateProp -State $uninstallState -Name "status" -Value "rebooting"
    Set-StateProp -State $uninstallState -Name "rebootRequestedAt" -Value (Get-Date).ToString("o")
    Save-State $uninstallState $UninstallFile

    Release-Lock
    Write-Log "Initiating reboot..." "WARN"
    # Shutdown in 60 seconds
    & shutdown.exe /s /t 60 /c "FameInstaller uninstall complete. Rebooting..."
    exit 0
  }

  Set-StateProp -State $uninstallState -Name "status" -Value "success"
  Set-StateProp -State $uninstallState -Name "completed" -Value (Get-Date).ToString("o")
  Set-StateProp -State $uninstallState -Name "uninstalledCount" -Value $uninstalledCount
  Set-StateProp -State $uninstallState -Name "failedCount" -Value $failedCount
  Save-State $uninstallState $UninstallFile

  Write-Log "State saved: $UninstallFile" "OK"
  Write-Log ("==== Completed. Uninstalled: {0}, Failed: {1} | Log: {2} ====" -f $uninstalledCount, $failedCount, $LogFile) "OK"
  Release-Lock
  exit 0
}
catch {
  Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
  Write-Log "Log file: $LogFile" "ERROR"

  try {
    $state = Load-UninstallState
    Set-StateProp -State $state -Name "status" -Value "fatal"
    Set-StateProp -State $state -Name "fatalAt" -Value (Get-Date).ToString("o")
    Set-StateProp -State $state -Name "fatalMessage" -Value $_.Exception.Message
    Save-State $state $UninstallFile
  } catch {}

  Release-Lock
  exit 1
}
