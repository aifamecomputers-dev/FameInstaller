[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("Alpa","Amax")]
  [string]$Org,

  [switch]$ContinueOnError,
  [switch]$DownloadOnly,

  # internal (used by scheduled task resume)
  [switch]$Resumed
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ----------------------------
# Paths / Logging / State
# ----------------------------
$BaseRoot  = "C:\ProgramData\FameInstaller"
$LogDir    = Join-Path $BaseRoot "logs"
$CacheDir  = Join-Path $BaseRoot ("cache\{0}" -f $Org)
$StateDir  = Join-Path $BaseRoot ("state\{0}" -f $Org)
New-Item -ItemType Directory -Force -Path $LogDir, $CacheDir, $StateDir | Out-Null

$Stamp     = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile   = Join-Path $LogDir ("install_{0}_{1}.log" -f $Org, $Stamp)
$StateFile = Join-Path $StateDir "installed.json"
$LockFile  = Join-Path $StateDir "install.lock"

# scheduled task name for resume
$TaskName  = "FameInstaller-Resume-$Org"

# reboot flag
$script:RebootRequired = $false

function Write-Log {
  param(
    [string]$Message,
    [ValidateSet("INFO","WARN","ERROR","OK")] [string]$Level="INFO"
  )
  $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
  $line | Tee-Object -FilePath $LogFile -Append | Out-Null
}

function Ensure-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  if (-not $isAdmin) {
    Write-Log "Not running as Administrator. Re-launching elevated..." "WARN"

    $args = @("-NoProfile","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"","-Org",$Org)
    if ($ContinueOnError) { $args += "-ContinueOnError" }
    if ($DownloadOnly)    { $args += "-DownloadOnly" }
    if ($Resumed)         { $args += "-Resumed" }

    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs | Out-Null
    exit 0
  }
}

function Acquire-Lock {
  # prevent two installers running at same time
  try {
    if (Test-Path $LockFile) {
      $age = (Get-Item $LockFile).LastWriteTime
      # if lock older than 6 hours, treat as stale
      if ($age -lt (Get-Date).AddHours(-6)) {
        Write-Log "Stale lock detected, clearing: $LockFile" "WARN"
        Remove-Item $LockFile -Force -ErrorAction SilentlyContinue
      } else {
        throw "Another FameInstaller run seems active (lock exists): $LockFile"
      }
    }
    Set-Content -Path $LockFile -Value ("{0} {1}" -f $env:COMPUTERNAME, (Get-Date).ToString("o")) -Encoding UTF8
  } catch { throw }
}

function Release-Lock {
  Remove-Item $LockFile -Force -ErrorAction SilentlyContinue | Out-Null
}

function Wait-For-InstallerIdle {
  param([int]$MaxMinutes = 45, [int]$PollSeconds = 10)

  $deadline = (Get-Date).AddMinutes($MaxMinutes)
  while ($true) {
    $msi = Get-Process -Name "msiexec" -ErrorAction SilentlyContinue
    if (-not $msi) { return }

    if ((Get-Date) -gt $deadline) {
      throw "Timed out waiting for other installations (msiexec) to finish."
    }

    Write-Log "Another installation is running (msiexec). Waiting..." "WARN"
    Start-Sleep -Seconds $PollSeconds
  }
}

function Get-RemoteInstallFiles {
  param([Parameter(Mandatory=$true)][string]$BaseUrl)

  $basicUrl = if ($BaseUrl.EndsWith("/")) { "$($BaseUrl)?get=basic" } else { "$($BaseUrl)/?get=basic" }

  Write-Log "Fetching file list: $basicUrl"
  $html = (Invoke-WebRequest -Uri $basicUrl -UseBasicParsing).Content

  $hrefs = @()
  $hrefs += [regex]::Matches($html, 'href="([^"]+)"', 'IgnoreCase') | ForEach-Object { $_.Groups[1].Value }
  $hrefs += [regex]::Matches($html, "href='([^']+)'",  'IgnoreCase') | ForEach-Object { $_.Groups[1].Value }

  $plain = [regex]::Matches($html, '(?i)[A-Za-z0-9][A-Za-z0-9 _\-\.\(\)%]*\.(exe|msi)') |
           ForEach-Object { $_.Value }

  $candidates = @($hrefs + $plain)

  $files = $candidates |
    Where-Object { $_ } |
    ForEach-Object { [System.Uri]::UnescapeDataString($_) } |
    ForEach-Object { $_.Trim() } |
    ForEach-Object { ($_ -split '[\?#]')[0] } |
    Where-Object { $_ -match '(?i)\.(exe|msi)$' } |
    Where-Object {
      $_ -notmatch '^\(2\)\.exe$' -and
      $_ -notmatch '^\.\.?/?$' -and
      $_ -notmatch '\.config$' -and
      $_ -notmatch '^application\.config$' -and
      $_ -notmatch '^user\.config$'
    } |
    Select-Object -Unique

  if (-not $files -or $files.Count -eq 0) {
    throw "No .exe/.msi installers found at $basicUrl"
  }

  return $files
}

function Test-IsHtmlFile {
  param([Parameter(Mandatory=$true)][string]$Path)
  $fs = [System.IO.File]::Open($Path,[System.IO.FileMode]::Open,[System.IO.FileAccess]::Read,[System.IO.FileShare]::ReadWrite)
  try {
    $buf = New-Object byte[] 2048
    $n = $fs.Read($buf,0,$buf.Length)
    $txt = [System.Text.Encoding]::ASCII.GetString($buf,0,$n)
    return ($txt -match '<!DOCTYPE html>|<html')
  } finally { $fs.Close() }
}

function Download-File {
  param([string]$Url, [string]$OutPath, [int]$Retries = 4)

  if (Test-Path $OutPath) { Write-Log "Cache hit: $OutPath"; return }

  for ($i=1; $i -le $Retries; $i++) {
    try {
      Write-Log "Downloading ($i/$Retries): $Url"
      Invoke-WebRequest -Uri $Url -OutFile $OutPath -UseBasicParsing -Headers @{ "Cache-Control"="no-cache" }

      if (-not (Test-Path $OutPath)) { throw "Download failed (file not created)." }
      try { Unblock-File -Path $OutPath -ErrorAction SilentlyContinue } catch {}

      if (Test-IsHtmlFile -Path $OutPath) {
        throw "Downloaded HTML instead of installer. URL blocked/WAF/auth issue: $Url"
      }

      Write-Log "Download OK: $OutPath" "OK"
      return
    } catch {
      Write-Log "Download error: $($_.Exception.Message)" "WARN"
      if ($i -eq $Retries) { throw }
      Start-Sleep -Seconds (3 * $i)
    }
  }
}

function Test-IsValidMsi {
  param([Parameter(Mandatory=$true)][string]$MsiPath)
  try {
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $db = $wi.OpenDatabase($MsiPath, 0)  # will throw if not a valid MSI
    $null = $db.SummaryInformation
    return $true
  } catch {
    return $false
  }
}

function Get-MsiProductCodeFromPackage {
  param([string]$MsiPath)
  try {
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $db = $wi.OpenDatabase($MsiPath, 0)
    $view = $db.OpenView("SELECT `Value` FROM `Property` WHERE `Property`='ProductCode'")
    $view.Execute()
    $rec = $view.Fetch()
    $code = $rec.StringData(1)
    $view.Close()
    return $code
  } catch { return $null }
}

function Test-MsiInstalledByProductCode {
  param([string]$ProductCode)
  if (-not $ProductCode) { return $false }

  $keys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$ProductCode"
  )
  foreach ($k in $keys) { if (Test-Path $k) { return $true } }
  return $false
}

function Get-UninstallRegistrySnapshot {
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  $items = foreach ($path in $paths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {

      $dnProp = $_.PSObject.Properties["DisplayName"]
      if (-not $dnProp -or [string]::IsNullOrWhiteSpace([string]$dnProp.Value)) { return }

      $get = {
        param($obj, [string]$name)
        $p = $obj.PSObject.Properties[$name]
        if ($p) { $p.Value } else { $null }
      }

      [pscustomobject]@{
        KeyName              = $_.PSChildName
        DisplayName          = [string]$dnProp.Value
        DisplayVersion       = (& $get $_ "DisplayVersion")
        Publisher            = (& $get $_ "Publisher")
        UninstallString      = (& $get $_ "UninstallString")
        QuietUninstallString = (& $get $_ "QuietUninstallString")
        InstallLocation      = (& $get $_ "InstallLocation")
        WindowsInstaller     = (& $get $_ "WindowsInstaller")
      }
    }
  }

  return @($items | Sort-Object KeyName, DisplayName)
}

function Find-NewUninstallEntries {
  param([object[]]$Before,[object[]]$After)

  $beforeIds = New-Object System.Collections.Generic.HashSet[string]
  foreach ($b in $Before) { [void]$beforeIds.Add("$($b.KeyName)|$($b.DisplayName)") }

  $new = @()
  foreach ($a in $After) {
    $id = "$($a.KeyName)|$($a.DisplayName)"
    if (-not $beforeIds.Contains($id)) { $new += $a }
  }
  return $new
}

function Get-InstallerSignature {
  param([string]$ExePath)

  # keep this lightweight, don't read whole file
  $max = 8MB
  $bytes = [System.IO.File]::ReadAllBytes($ExePath)
  if ($bytes.Length -gt $max) { $bytes = $bytes[0..($max-1)] }
  $text = [System.Text.Encoding]::ASCII.GetString($bytes)

  if ($text -match 'Inno Setup') { return "INNO" }
  if ($text -match 'Nullsoft Install System|NSIS') { return "NSIS" }
  if ($text -match 'InstallShield') { return "IS" }
  if ($text -match 'WiX Toolset') { return "WIX" }
  return "UNKNOWN"
}

function Get-ExeArgCandidates {
  param([string]$FileName,[string]$Signature)

  # Special cases
  if ($FileName -match '^NetFx64\.exe$') { return @("/q /norestart", "/quiet /norestart", "/passive /norestart") }
  if ($FileName -match '^Reader_.*\.exe$') { return @("/sAll /rs /rps /msi EULA_ACCEPT=YES", "/S", "/quiet /norestart") }
  if ($FileName -match '^Splashtop_Streamer_.*\.exe$') { return @("/quiet /norestart", "/silent", "/S", "/verysilent /norestart") }

  switch ($Signature) {
    "INNO" { return @("/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-", "/SILENT /NORESTART /SP-") }
    "NSIS" { return @("/S") }
    "IS"   { return @("/s /v`"/qn /norestart`"", "/s") }
    "WIX"  { return @("/quiet /norestart", "/q") }
    default { return @("/quiet /norestart","/q /norestart","/S","/silent","/verysilent /norestart","/s /v`"/qn /norestart`"") }
  }
}

function Invoke-MsiInstall {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [string]$ProductCode = $null,
    [int]$Retries = 3
  )

  if (-not (Test-IsValidMsi -MsiPath $Path)) {
    return 1620
  }

  if ($ProductCode -and (Test-MsiInstalledByProductCode -ProductCode $ProductCode)) {
    Write-Log "MSI already installed (ProductCode=$ProductCode). Skipping: $Path" "OK"
    return 0
  }

  Wait-For-InstallerIdle
  $args = "/i `"$Path`" /qn /norestart"
  Write-Log "MSI: msiexec.exe $args"
  if ($DownloadOnly) { Write-Log "DownloadOnly: skipping execution" "WARN"; return 0 }

  for ($i=1; $i -le $Retries; $i++) {
    $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
    $code = [int]$p.ExitCode

    if ($code -eq 0) { return 0 }
    if ($code -eq 3010 -or $code -eq 1641) { $script:RebootRequired = $true; return $code }
    if ($code -eq 1618) {
      Write-Log "MSI exit 1618 (another install in progress). Waiting/retrying ($i/$Retries)..." "WARN"
      Wait-For-InstallerIdle
      Start-Sleep -Seconds (5 * $i)
      continue
    }
    return $code
  }

  return 1618
}

function Invoke-ExeInstall {
  param([string]$Path)

  Wait-For-InstallerIdle
  $fileName   = Split-Path -Leaf $Path
  $sig        = Get-InstallerSignature -ExePath $Path
  $candidates = Get-ExeArgCandidates -FileName $fileName -Signature $sig | Select-Object -Unique

  $timeoutMinutes = if ($fileName -ieq "NetFx64.exe") { 40 } else { 25 }

  foreach ($a in $candidates) {
    try {
      Write-Log "EXE: `"$fileName`" signature=$sig args=$a timeout=${timeoutMinutes}m"
      if ($DownloadOnly) { Write-Log "DownloadOnly: skipping execution" "WARN"; return 0 }

      $p = Start-Process -FilePath $Path -ArgumentList $a -PassThru

      $deadline = (Get-Date).AddMinutes($timeoutMinutes)
      while (-not $p.HasExited) {
        if ((Get-Date) -gt $deadline) {
          Write-Log "Timeout waiting for $fileName. Killing PID=$($p.Id)..." "ERROR"
          try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
          throw "Timeout installing $fileName (possible UI/SmartScreen block or hung installer)."
        }
        Start-Sleep -Seconds 5
        try { $p.Refresh() } catch {}
      }

      $code = [int]$p.ExitCode

      if ($code -eq 0) { return 0 }
      if ($code -eq 3010 -or $code -eq 1641) { $script:RebootRequired = $true; return $code }
      if ($code -eq 1618) { Write-Log "Exit 1618. Waiting then retry..." "WARN"; Wait-For-InstallerIdle; continue }
      if ($code -eq 1638) { Write-Log "Exit 1638 (already installed). Treating OK." "WARN"; return 0 }

      Write-Log "Attempt failed: exit=$code (args=$a)" "WARN"
    } catch {
      Write-Log "Attempt exception: $($_.Exception.Message) (args=$a)" "WARN"
    }
  }

  throw "All silent install attempts failed for: $fileName"
}

function Load-State {
  if (Test-Path $StateFile) {
    try { return (Get-Content $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { }
  }
  return [pscustomobject]@{
    org=$Org
    created=(Get-Date).ToString("o")
    items=@()
    completed=$false
  }
}

function Save-State($state) {
  $state | ConvertTo-Json -Depth 12 | Set-Content -Path $StateFile -Encoding UTF8
}

function Test-AlreadyInstalledByState {
  param([object]$state, [string]$fileName)
  foreach ($it in $state.items) {
    if ($it.file -eq $fileName -and [int]$it.exitCode -in @(0,3010,1641,1638)) { return $true }
  }
  return $false
}

function Ensure-ResumeTask {
  param([string]$ScriptPath)

  # create/replace a scheduled task that runs once at startup
  $ps = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Org $Org"
  if ($ContinueOnError) { $argList += " -ContinueOnError" }
  if ($DownloadOnly)    { $argList += " -DownloadOnly" }
  $argList += " -Resumed"

  $action  = New-ScheduledTaskAction -Execute $ps -Argument $argList
  $trigger = New-ScheduledTaskTrigger -AtStartup

  # Run as SYSTEM for reliability after reboot
  $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest

  try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
  } catch {}

  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal | Out-Null
  Write-Log "Resume task created: $TaskName" "OK"
}

function Remove-ResumeTask {
  try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Write-Log "Resume task removed: $TaskName" "OK"
  } catch {}
}

# ----------------------------
# MAIN
# ----------------------------
try {
  Ensure-Admin
  Acquire-Lock

  Write-Log "==== Fame Folder Installer start | Org=$Org | Host=$env:COMPUTERNAME | Resumed=$Resumed ===="

  $baseUrl = if ($Org -eq "Alpa") { "https://file.famepbx.com/alpa/" } else { "https://file.famepbx.com/amax/" }
  $files = Get-RemoteInstallFiles -BaseUrl $baseUrl

  $dotnet = $files | Where-Object { $_ -ieq "NetFx64.exe" }
  $msis   = $files | Where-Object { $_ -match '(?i)\.msi$' } | Sort-Object
  $exes   = $files | Where-Object { $_ -match '(?i)\.exe$' -and $_ -ine "NetFx64.exe" } | Sort-Object

  $plan = @()
  if ($dotnet) { $plan += $dotnet }
  $plan += $msis
  $plan += $exes

  Write-Log ("Install plan ({0} items): {1}" -f $plan.Count, ($plan -join ", "))

  $state = Load-State

  foreach ($f in $plan) {
    try {
      # Skip already-done items (resume safe)
      if (Test-AlreadyInstalledByState -state $state -fileName $f) {
        Write-Log "Already completed earlier. Skipping: $f" "OK"
        continue
      }

      $url   = $baseUrl.TrimEnd("/") + "/" + [uri]::EscapeDataString($f).Replace("+","%20")
      $local = Join-Path $CacheDir $f
      Download-File -Url $url -OutPath $local

      # extra safety: validate non-html after download
      if (Test-IsHtmlFile -Path $local) { throw "Downloaded HTML instead of installer: $f" }

      $before = Get-UninstallRegistrySnapshot

      $pkgType = "exe"
      if ($f -match '(?i)\.msi$') { $pkgType = "msi" }

      $record = [ordered]@{
        file = $f
        local = $local
        type = $pkgType
        installedAt = (Get-Date).ToString("o")
        exitCode = $null
        msiProductCode = $null
        uninstallEntries = @()
      }

      $exit = 0
      if ($pkgType -eq "msi") {
        $record.msiProductCode = Get-MsiProductCodeFromPackage -MsiPath $local
        $exit = Invoke-MsiInstall -Path $local -ProductCode $record.msiProductCode
      } else {
        $exit = Invoke-ExeInstall -Path $local
      }

      $record.exitCode = [int]$exit

      $after = Get-UninstallRegistrySnapshot
      $newEntries = Find-NewUninstallEntries -Before $before -After $after

      $record.uninstallEntries = @(
        $newEntries |
          Where-Object { $_.UninstallString -or $_.QuietUninstallString } |
          Select-Object KeyName, DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString, WindowsInstaller
      )

      $state.items += [pscustomobject]$record
      Save-State $state

      $exitNum = [int]$exit
      if ($exitNum -eq 0 -or $exitNum -eq 1638) {
        Write-Log "Installed OK: $f" "OK"
      } elseif ($exitNum -eq 3010 -or $exitNum -eq 1641) {
        Write-Log "Installed OK (reboot required): $f" "WARN"
      } elseif ($exitNum -eq 1620) {
        throw "MSI invalid/unopenable (1620). Likely bad package or blocked download."
      } else {
        throw "Installer returned exit code $exitNum"
      }

      # Auto-reboot and resume if required
      if ($script:RebootRequired -and -not $DownloadOnly) {
        # Prepare resume task to continue after reboot
        Ensure-ResumeTask -ScriptPath $PSCommandPath
        Write-Log "Reboot required detected. Restarting now to continue installation..." "WARN"
        Release-Lock
        Restart-Computer -Force
        exit 0
      }

    } catch {
      Write-Log "FAILED: $f :: $($_.Exception.Message)" "ERROR"
      if (-not $ContinueOnError) { throw }
    }
  }

  $state.completed = $true
  Save-State $state

  # If we were resumed, remove the resume task when done
  Remove-ResumeTask

  Write-Log "State saved: $StateFile" "OK"
  Write-Log "==== Completed successfully. Log: $LogFile ====" "OK"

  Release-Lock
  exit 0
}
catch {
  Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
  Write-Log "Log file: $LogFile" "ERROR"
  Release-Lock
  exit 1
}
