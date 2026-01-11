<# 
FameInstaller - install_v1.ps1 (FINAL)
- Installs all EXE/MSI in https://file.famepbx.com/{org}/
- Priority: NetFx64.exe first (if present), then MSIs, then other EXEs
- Safe for Windows PowerShell 5.1 (no ternary, no null-conditional)
- Single-run lock to prevent parallel runs
- Cache + validation (detects HTML/partial downloads; re-downloads once)
- Tracks uninstall info to C:\ProgramData\FameInstaller\state\<Org>\installed.json
- Handles reboot-required exit codes (3010/1641) and can auto-resume after reboot (Scheduled Task)
- UI-required: PP14Downloader + Adobe Reader installer (per request)
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("Alpa","Amax")]
  [string]$Org,

  [switch]$ContinueOnError,
  [switch]$DownloadOnly,

  # Optional override to bypass DNS/hairpin issues:
  # e.g. -BaseUrlOverride "https://192.168.50.10/amax/"
  [string]$BaseUrlOverride,

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
$CacheDir = Join-Path $BaseRoot ("cache\{0}" -f $Org)
$StateDir = Join-Path $BaseRoot ("state\{0}" -f $Org)

New-Item -ItemType Directory -Force -Path $LogDir, $CacheDir, $StateDir | Out-Null

$Stamp     = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile   = Join-Path $LogDir ("install_{0}_{1}.log" -f $Org, $Stamp)
$StateFile = Join-Path $StateDir "installed.json"
$LockFile  = Join-Path $StateDir "install.lock"

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
    if ($DownloadOnly)    { $args += "-DownloadOnly" }
    if ($BaseUrlOverride) { $args += @("-BaseUrlOverride",$BaseUrlOverride) }
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
      throw "Another FameInstaller run seems active (PID=$($lock.pid)). Lock: $LockFile"
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

    Write-Log "Another installation is running (msiexec). Waiting..." "WARN"
    Start-Sleep -Seconds $PollSeconds
  }
}

# ----------------------------
# Web + Download helpers
# ----------------------------
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

  if (-not $files -or $files.Count -eq 0) { throw "No .exe/.msi installers found at $basicUrl" }
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
  } finally {
    $fs.Close()
  }
}

function Download-File {
  param(
    [Parameter(Mandatory=$true)][string]$Url,
    [Parameter(Mandatory=$true)][string]$OutPath,
    [int]$Retries = 4
  )

  if (Test-Path $OutPath) { Write-Log "Cache hit: $OutPath"; return }

  for ($i=1; $i -le $Retries; $i++) {
    try {
      Write-Log "Downloading ($i/$Retries): $Url"
      Invoke-WebRequest -Uri $Url -OutFile $OutPath -UseBasicParsing -Headers @{ "Cache-Control"="no-cache" }
      if (-not (Test-Path $OutPath)) { throw "Download failed (file not created)." }

      try { Unblock-File -Path $OutPath -ErrorAction SilentlyContinue } catch {}

      if (Test-IsHtmlFile -Path $OutPath) {
        throw "Downloaded HTML instead of installer (blocked/403/404). URL: $Url"
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

# ----------------------------
# MSI helpers
# ----------------------------
function Test-IsValidMsi {
  param([Parameter(Mandatory=$true)][string]$MsiPath)

  if (-not (Test-Path $MsiPath)) { return $false }
  if (Test-IsHtmlFile -Path $MsiPath) { return $false }

  try {
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $db = $wi.OpenDatabase($MsiPath, 0)
    $null = $db.SummaryInformation
    return $true
  } catch {
    return $false
  }
}

function Get-MsiProductCodeFromPackage {
  param([Parameter(Mandatory=$true)][string]$MsiPath)

  try {
    $wi = New-Object -ComObject WindowsInstaller.Installer
    $db = $wi.OpenDatabase($MsiPath, 0)
    $view = $db.OpenView("SELECT `Value` FROM `Property` WHERE `Property`='ProductCode'")
    $view.Execute()
    $rec = $view.Fetch()
    $code = $null
    if ($rec) { $code = $rec.StringData(1) }
    $view.Close()
    return $code
  } catch {
    return $null
  }
}

function Test-MsiInstalledByProductCode {
  param([Parameter(Mandatory=$true)][string]$ProductCode)

  try { $null = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{$ProductCode}" -ErrorAction Stop; return $true } catch {}
  try { $null = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{$ProductCode}" -ErrorAction Stop; return $true } catch {}
  return $false
}

# ----------------------------
# EXE signature + args (best-effort)
# ----------------------------
function Get-InstallerSignature {
  param([Parameter(Mandatory=$true)][string]$ExePath)

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
  param(
    [Parameter(Mandatory=$true)][string]$FileName,
    [Parameter(Mandatory=$true)][string]$Signature
  )

  if ($FileName -match '^NetFx64\.exe$') { return @("/q /norestart", "/quiet /norestart") }
  if ($FileName -match '^Reader_.*\.exe$') { return @("/sAll /rs /rps /msi EULA_ACCEPT=YES", "/quiet /norestart", "/S") }
  if ($FileName -match '^Splashtop_Streamer_.*\.exe$') { return @("/quiet /norestart", "/silent", "/S", "/verysilent /norestart") }

  switch ($Signature) {
    "INNO" { return @("/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-", "/SILENT /NORESTART /SP-") }
    "NSIS" { return @("/S") }
    "IS"   { return @("/s /v`"/qn /norestart`"", "/s") }
    "WIX"  { return @("/quiet /norestart", "/q") }
    default { return @("/quiet /norestart","/q /norestart","/S","/silent","/verysilent /norestart","/s /v`"/qn /norestart`"") }
  }
}

# ----------------------------
# Uninstall registry snapshot (for EXE tracking)
# ----------------------------
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
  param(
    [Parameter(Mandatory=$true)][object[]]$Before,
    [Parameter(Mandatory=$true)][object[]]$After
  )

  $beforeIds = New-Object System.Collections.Generic.HashSet[string]
  foreach ($b in $Before) { [void]$beforeIds.Add("$($b.KeyName)|$($b.DisplayName)") }

  $new = @()
  foreach ($a in $After) {
    $id = "$($a.KeyName)|$($a.DisplayName)"
    if (-not $beforeIds.Contains($id)) { $new += $a }
  }
  return $new
}

# ----------------------------
# State handling (StrictMode-safe)
# ----------------------------
function Load-State {
  if (Test-Path $StateFile) {
    try {
      $s = Get-Content $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json
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

function Save-State($state) {
  $state | ConvertTo-Json -Depth 20 | Set-Content -Path $StateFile -Encoding UTF8
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
# Resume-after-reboot (Scheduled Task)
# ----------------------------
function Register-ResumeTask {
  param(
    [Parameter(Mandatory=$true)][string]$ScriptPath,
    [Parameter(Mandatory=$true)][string]$OrgName
  )

  $taskName = "FameInstaller-Resume-$OrgName"
  $actionArgs = @(
    "-NoProfile",
    "-ExecutionPolicy","Bypass",
    "-File","`"$ScriptPath`"",
    "-Org",$OrgName,
    "-Resumed"
  )
  if ($ContinueOnError) { $actionArgs += "-ContinueOnError" }
  if ($DownloadOnly)    { $actionArgs += "-DownloadOnly" }
  if ($BaseUrlOverride) { $actionArgs += @("-BaseUrlOverride",$BaseUrlOverride) }

  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument ($actionArgs -join " ")
  $trigger = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

  try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch {}
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
  Write-Log "Registered resume task: $taskName" "OK"
}

function Unregister-ResumeTask {
  param([Parameter(Mandatory=$true)][string]$OrgName)
  $taskName = "FameInstaller-Resume-$OrgName"
  try {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
    Write-Log "Removed resume task: $taskName" "OK"
  } catch {}
}

# ----------------------------
# Install executors
# ----------------------------
function Invoke-MsiInstall {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [object]$ProductCode = $null,
    [int]$Retries = 3
  )

  $pc = $null
  if ($ProductCode) { $pc = [string]($ProductCode | Select-Object -First 1) }

  if (-not (Test-IsValidMsi -MsiPath $Path)) { return 1620 }

  if ($pc) {
    try {
      if (Test-MsiInstalledByProductCode -ProductCode $pc) {
        Write-Log "MSI already installed (ProductCode=$pc). Skipping: $Path" "OK"
        return 0
      }
    } catch { }
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
  param([Parameter(Mandatory=$true)][string]$Path)

  Wait-For-InstallerIdle

  $fileName = Split-Path -Leaf $Path
  $sig = Get-InstallerSignature -ExePath $Path
  $candidates = @(Get-ExeArgCandidates -FileName $fileName -Signature $sig | Select-Object -Unique)

  $timeoutMinutes = 25
  if ($fileName -ieq "NetFx64.exe") { $timeoutMinutes = 40 }

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
          throw "Timeout installing $fileName (hung UI/SmartScreen)."
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

function Invoke-UiExeAndWait {
  param([Parameter(Mandatory=$true)][string]$Path)

  Wait-For-InstallerIdle

  $fileName = Split-Path -Leaf $Path
  Write-Log "UI installer required. Launching and waiting for user: $fileName" "WARN"

  if ($DownloadOnly) { Write-Log "DownloadOnly: skipping UI execution" "WARN"; return 0 }

  $p = Start-Process -FilePath $Path -PassThru
  $p.WaitForExit()

  $code = [int]$p.ExitCode
  Write-Log "UI installer exit code: $code ($fileName)" "INFO"

  if ($code -eq 0) { return 0 }
  if ($code -eq 3010 -or $code -eq 1641) { $script:RebootRequired = $true; return $code }

  return $code
}

# ----------------------------
# MAIN
# ----------------------------
try {
  Ensure-Admin
  Acquire-Lock

  Write-Log ("==== Fame Folder Installer start | Org={0} | Host={1} | Resumed={2} ====" -f $Org, $env:COMPUTERNAME, ([bool]$Resumed))

  # ----------------------------
  # Hairpin NAT Detection & Fix
  # ----------------------------
  function Test-HairpinNATIssue {
    param([string]$Domain)
    
    try {
      # Check if we can resolve the domain
      $resolved = [System.Net.Dns]::GetHostAddresses($Domain)
      if (-not $resolved) { return $false }
      
      $publicIP = $resolved[0].IPAddressToString
      
      # Get local network adapter IPs (excluding loopback)
      $localIPs = Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Manual,Dhcp -ErrorAction SilentlyContinue | 
                  Where-Object { $_.IPAddress -notmatch '^127\.' -and $_.IPAddress -notmatch '^169\.254\.' } |
                  Select-Object -ExpandProperty IPAddress
      
      # Check if the public domain resolves to a local network IP (same subnet)
      foreach ($localIP in $localIPs) {
        $localOctets = $localIP.Split('.')
        $publicOctets = $publicIP.Split('.')
        
        # Check if first 3 octets match (same /24 subnet)
        if ($localOctets[0] -eq $publicOctets[0] -and 
            $localOctets[1] -eq $publicOctets[1] -and 
            $localOctets[2] -eq $publicOctets[2]) {
          Write-Log "Hairpin NAT detected: $Domain resolves to local network IP $publicIP" "WARN"
          return $publicIP
        }
      }
      
      return $false
    } catch {
      Write-Log "Could not test for Hairpin NAT: $($_.Exception.Message)" "WARN"
      return $false
    }
  }

  $baseUrl = $null
  if ($BaseUrlOverride) {
    $baseUrl = $BaseUrlOverride
  } else {
    if ($Org -eq "Alpa") { $baseUrl = "https://file.famepbx.com/alpa/" } else { $baseUrl = "https://file.famepbx.com/amax/" }
    
    # Check for Hairpin NAT issue
    $localIP = Test-HairpinNATIssue -Domain "file.famepbx.com"
    if ($localIP) {
      $orgPath = if ($Org -eq "Alpa") { "alpa" } else { "amax" }
      $baseUrl = "https://$localIP/$orgPath/"
      Write-Log "Using local IP to avoid Hairpin NAT: $baseUrl" "OK"
    }
  }

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
  Set-StateProp -State $state -Name "status" -Value "running"
  Set-StateProp -State $state -Name "lastStart" -Value (Get-Date).ToString("o")
  Save-State $state

  # UI installers (ADD READER HERE ✅)
  $uiExeList = @(
    "PP14Downloader_1_0_35_0.EXE",
    "Reader_en_install (2).exe"
  )

  foreach ($f in $plan) {
    try {
      $url   = $baseUrl.TrimEnd("/") + "/" + [uri]::EscapeDataString($f).Replace("+","%20")
      $local = Join-Path $CacheDir $f

      Download-File -Url $url -OutPath $local

      # For MSIs: validate; if invalid cached, delete + re-download once
      if ($f -match '(?i)\.msi$') {
        if (-not (Test-IsValidMsi -MsiPath $local)) {
          Write-Log "Cached MSI invalid. Deleting + re-downloading: $f" "WARN"
          Remove-Item $local -Force -ErrorAction SilentlyContinue | Out-Null
          Download-File -Url $url -OutPath $local
          if (-not (Test-IsValidMsi -MsiPath $local)) {
            throw "MSI invalid/unopenable (1620). Likely bad package or blocked download."
          }
        }
      }

      $before = Get-UninstallRegistrySnapshot

      $exit = 0
      $pkgType = "exe"
      if ($f -match '(?i)\.msi$') { $pkgType = "msi" }

      $record = [ordered]@{
        file            = $f
        local           = $local
        type            = $pkgType
        installedAt     = (Get-Date).ToString("o")
        exitCode        = $null
        msiProductCode  = $null
        uninstallEntries = @()
        notes           = $null
      }

      if ($f -match '(?i)\.msi$') {
        $pc = Get-MsiProductCodeFromPackage -MsiPath $local
        if ($pc) { $pc = [string]($pc | Select-Object -First 1) } else { $pc = $null }
        $record.msiProductCode = $pc
        $exit = Invoke-MsiInstall -Path $local -ProductCode $pc

        if ($exit -eq 1620) {
          throw "MSI invalid/unopenable (1620). Likely bad package or blocked download."
        }

      } else {
        if ($uiExeList -contains $f) {
          $record.notes = "UI-required"
          $exit = Invoke-UiExeAndWait -Path $local
        } else {
          $exit = Invoke-ExeInstall -Path $local
        }
      }

      $record.exitCode = [int]$exit

      $after = Get-UninstallRegistrySnapshot
      $newEntries = Find-NewUninstallEntries -Before $before -After $after

      $record.uninstallEntries = @(
        $newEntries |
          Where-Object { $_.UninstallString -or $_.QuietUninstallString } |
          Select-Object KeyName, DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString, WindowsInstaller
      )

      $items = @()
      if ($state.PSObject.Properties.Match("items").Count -gt 0) { $items = @($state.items) }
      $items += [pscustomobject]$record
      Set-StateProp -State $state -Name "items" -Value $items
      Set-StateProp -State $state -Name "lastItem" -Value $f
      Set-StateProp -State $state -Name "lastUpdate" -Value (Get-Date).ToString("o")
      Save-State $state

      if ($exit -eq 0) {
        Write-Log "Installed OK: $f" "OK"
      } elseif ($exit -eq 3010 -or $exit -eq 1641) {
        Write-Log "Installed OK (reboot required): $f" "WARN"
      } elseif ($exit -eq 1638) {
        Write-Log "Already installed: $f" "WARN"
      } else {
        throw "Installer returned exit code $exit"
      }

    } catch {
      Write-Log "FAILED: $f :: $($_.Exception.Message)" "ERROR"

      try {
        $failRec = [pscustomobject]@{
          file        = $f
          failedAt    = (Get-Date).ToString("o")
          message     = $_.Exception.Message
        }
        $fails = @()
        if ($state.PSObject.Properties.Match("failures").Count -gt 0) { $fails = @($state.failures) }
        $fails += $failRec
        Set-StateProp -State $state -Name "failures" -Value $fails
        Set-StateProp -State $state -Name "lastUpdate" -Value (Get-Date).ToString("o")
        Save-State $state
      } catch {}

      if (-not $ContinueOnError) { throw }
    }
  }

  if ($script:RebootRequired -and -not $DownloadOnly) {
    Write-Log "Reboot required detected. Scheduling auto-resume after reboot..." "WARN"
    Register-ResumeTask -ScriptPath $PSCommandPath -OrgName $Org

    Set-StateProp -State $state -Name "status" -Value "rebooting"
    Set-StateProp -State $state -Name "rebootRequestedAt" -Value (Get-Date).ToString("o")
    Save-State $state

    Release-Lock
    Write-Log "Rebooting now..." "WARN"
    Restart-Computer -Force
    exit 0
  }

  Unregister-ResumeTask -OrgName $Org

  Set-StateProp -State $state -Name "status" -Value "success"
  Set-StateProp -State $state -Name "completed" -Value (Get-Date).ToString("o")
  Save-State $state

  Write-Log "State saved: $StateFile" "OK"
  Write-Log "==== Completed successfully. Log: $LogFile ====" "OK"
  Release-Lock
  exit 0
}
catch {
  Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
  Write-Log "Log file: $LogFile" "ERROR"

  try {
    $state = Load-State
    Set-StateProp -State $state -Name "status" -Value "fatal"
    Set-StateProp -State $state -Name "fatalAt" -Value (Get-Date).ToString("o")
    Set-StateProp -State $state -Name "fatalMessage" -Value $_.Exception.Message
    Save-State $state
  } catch {}

  Release-Lock
  exit 1
}