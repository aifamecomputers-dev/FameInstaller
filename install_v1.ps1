[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("Alpa","Amax")]
  [string]$Org,

  [switch]$ContinueOnError,
  [switch]$DownloadOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ----------------------------
# Paths / Logging / State
# ----------------------------
$BaseRoot = "C:\ProgramData\FameInstaller"
$LogDir   = Join-Path $BaseRoot "logs"
$CacheDir = Join-Path $BaseRoot ("cache\{0}" -f $Org)
$StateDir = Join-Path $BaseRoot ("state\{0}" -f $Org)
New-Item -ItemType Directory -Force -Path $LogDir, $CacheDir, $StateDir | Out-Null

$Stamp     = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile   = Join-Path $LogDir ("install_{0}_{1}.log" -f $Org, $Stamp)
$StateFile = Join-Path $StateDir "installed.json"

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
    if ($DownloadOnly)    { $args += "-DownloadOnly" }
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

function Get-RemoteInstallFiles {
  param([Parameter(Mandatory=$true)][string]$BaseUrl)

  # PowerShell 5.1-safe string interpolation (avoid "$BaseUrl?get=basic")
  $basicUrl = if ($BaseUrl.EndsWith("/")) { "$($BaseUrl)?get=basic" } else { "$($BaseUrl)/?get=basic" }

  Write-Log "Fetching file list: $basicUrl"
  $html = (Invoke-WebRequest -Uri $basicUrl -UseBasicParsing).Content

  # 1) Collect href values (double + single quotes)
  $hrefs = @()
  $hrefs += [regex]::Matches($html, 'href="([^"]+)"', 'IgnoreCase') | ForEach-Object { $_.Groups[1].Value }
  $hrefs += [regex]::Matches($html, "href='([^']+)'",  'IgnoreCase') | ForEach-Object { $_.Groups[1].Value }

  # 2) Collect plain-text filenames anywhere in content
  # (this catches listings that are not traditional <a href>)
  $plain = [regex]::Matches($html, '(?i)[A-Za-z0-9][A-Za-z0-9 _\-\.\(\)%]*\.(exe|msi)') |
           ForEach-Object { $_.Value }

  $candidates = @($hrefs + $plain)

  # Normalize + decode + filter
  $files = $candidates |
    Where-Object { $_ } |
    ForEach-Object { [System.Uri]::UnescapeDataString($_) } |
    ForEach-Object { $_.Trim() } |
    # Only final filenames (strip any query strings/fragments)
    ForEach-Object { ($_ -split '[\?#]')[0] } |
    # Keep only exe/msi
    Where-Object { $_ -match '(?i)\.(exe|msi)$' } |
    # Drop obvious garbage cases
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


function Download-File {
  param([string]$Url, [string]$OutPath, [int]$Retries = 4)

  if (Test-Path $OutPath) { Write-Log "Cache hit: $OutPath"; return }

  for ($i=1; $i -le $Retries; $i++) {
    try {
      Write-Log "Downloading ($i/$Retries): $Url"
      Invoke-WebRequest -Uri $Url -OutFile $OutPath -UseBasicParsing -Headers @{ "Cache-Control"="no-cache" }
      if (-not (Test-Path $OutPath)) { throw "Download failed (file not created)." }

      # Helpful: reduce SmartScreen/MOTW issues
      try { Unblock-File -Path $OutPath -ErrorAction SilentlyContinue } catch {}

        # Fail fast if we downloaded an HTML error page (WAF/403/404) — binary-safe
        try {
        $fs = [System.IO.File]::Open($OutPath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)
        try {
            $buf = New-Object byte[] 2048
            $n = $fs.Read($buf, 0, $buf.Length)
            $txt = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
            if ($txt -match '<!DOCTYPE html>|<html') {
            throw "Downloaded HTML instead of installer. URL may be blocked or requires auth: $Url"
            }
        } finally {
            $fs.Close()
        }
        } catch {
        Write-Log "Binary header check skipped: $($_.Exception.Message)" "WARN"
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

# -------- Registry inventory (for EXE uninstall tracking) --------
function Get-UninstallRegistrySnapshot {
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
  )

  $items = foreach ($path in $paths) {
    Get-ItemProperty $path -ErrorAction SilentlyContinue | ForEach-Object {

      # StrictMode-safe: DisplayName may not exist
      $dnProp = $_.PSObject.Properties["DisplayName"]
      if (-not $dnProp -or [string]::IsNullOrWhiteSpace([string]$dnProp.Value)) { return }

      # Safe property getter for PS5.1
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

  # IMPORTANT: return an array, sorted, so your diff logic works consistently
  return @($items | Sort-Object KeyName, DisplayName)
}




function Find-NewUninstallEntries {
  param(
    [object[]]$Before,
    [object[]]$After
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

function Get-InstallerSignature {
  param([string]$ExePath)
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
  param([string]$FileName, [string]$Signature)

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

function Invoke-MsiInstall {
  param([string]$Path)
  Wait-For-InstallerIdle
  $args = "/i `"$Path`" /qn /norestart"
  Write-Log "MSI: msiexec.exe $args"
  if ($DownloadOnly) { Write-Log "DownloadOnly: skipping execution" "WARN"; return 0 }
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
  return $p.ExitCode
}

function Invoke-ExeInstall {
  param([string]$Path)
  Wait-For-InstallerIdle
  $fileName = Split-Path -Leaf $Path
  $sig = Get-InstallerSignature -ExePath $Path
  $candidates = Get-ExeArgCandidates -FileName $fileName -Signature $sig | Select-Object -Unique

  foreach ($a in $candidates) {
    try {
      Write-Log "EXE: `"$fileName`" signature=$sig args=$a"
      if ($DownloadOnly) { Write-Log "DownloadOnly: skipping execution" "WARN"; return 0 }
      $p = Start-Process -FilePath $Path -ArgumentList $a -Wait -PassThru
      $code = $p.ExitCode
      if ($code -eq 0 -or $code -eq 3010) { return $code }
      if ($code -eq 1618) { Write-Log "Exit 1618. Waiting then retry..." "WARN"; Wait-For-InstallerIdle; continue }
      if ($code -eq 1638) { Write-Log "Exit 1638 (already installed). Treating OK." "WARN"; return 0 }
      Write-Log "Attempt failed: exit=$code (args=$a)" "WARN"
    } catch {
      Write-Log "Attempt exception: $($_.Exception.Message) (args=$a)" "WARN"
    }
  }
  throw "All silent install attempts failed for: $fileName"
}

# ---- MSI product code capture (so uninstaller can be exact) ----
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
  } catch {
    return $null
  }
}

# ---- State handling ----
function Load-State {
  if (Test-Path $StateFile) {
    try { return (Get-Content $StateFile -Raw -Encoding UTF8 | ConvertFrom-Json) } catch { }
  }
  return [pscustomobject]@{ org=$Org; created=(Get-Date).ToString("o"); items=@() }
}

function Save-State($state) {
  $state | ConvertTo-Json -Depth 10 | Set-Content -Path $StateFile -Encoding UTF8
}

# ----------------------------
# MAIN
# ----------------------------
try {
  Ensure-Admin
  Write-Log "==== Fame Folder Installer start | Org=$Org | Host=$env:COMPUTERNAME ===="

  $baseUrl = if ($Org -eq "Alpa") { "https://file.famepbx.com/alpa/" } else { "https://file.famepbx.com/amax/" }
  $files = Get-RemoteInstallFiles -BaseUrl $baseUrl

  $dotnet = $files | Where-Object { $_ -ieq "NetFx64.exe" }
  $msis   = $files | Where-Object { $_ -match '\.msi$' } | Sort-Object
  $exes   = $files | Where-Object { $_ -match '\.exe$' -and $_ -ine "NetFx64.exe" } | Sort-Object

  $plan = @()
  if ($dotnet) { $plan += $dotnet }
  $plan += $msis
  $plan += $exes

  Write-Log ("Install plan ({0} items): {1}" -f $plan.Count, ($plan -join ", "))

  $state = Load-State

  foreach ($f in $plan) {
    try {
      $url   = $baseUrl.TrimEnd("/") + "/" + [uri]::EscapeDataString($f).Replace("+","%20")
      $local = Join-Path $CacheDir $f
      Download-File -Url $url -OutPath $local

      # snapshot before (to detect new EXE uninstall entries)
      $before = Get-UninstallRegistrySnapshot

      $exit = 0
      $record = [ordered]@{
        file = $f
        local = $local
        type = (if ($f -match '\.msi$') { "msi" } else { "exe" })   # PowerShell 5.1-safe
        installedAt = (Get-Date).ToString("o")
        exitCode = $null
        msiProductCode = $null
        uninstallEntries = @()
      }

      if ($f -match '\.msi$') {
        $record.msiProductCode = Get-MsiProductCodeFromPackage -MsiPath $local
        $exit = Invoke-MsiInstall -Path $local
      } else {
        $exit = Invoke-ExeInstall -Path $local
      }

      $record.exitCode = $exit

      # snapshot after
      $after = Get-UninstallRegistrySnapshot
      $newEntries = Find-NewUninstallEntries -Before $before -After $after

      # store only entries that look relevant (have uninstall strings)
      $record.uninstallEntries = @(
        $newEntries | Where-Object { $_.UninstallString -or $_.QuietUninstallString } |
          Select-Object KeyName, DisplayName, DisplayVersion, Publisher, UninstallString, QuietUninstallString, WindowsInstaller
      )

      # write state incrementally
      $state.items += [pscustomobject]$record
      Save-State $state

      if ($exit -eq 0) {
        Write-Log "Installed OK: $f" "OK"
      } elseif ($exit -eq 3010) {
        Write-Log "Installed OK (reboot required): $f" "WARN"
      } else {
        throw "Installer returned exit code $exit"
      }
    } catch {
      Write-Log "FAILED: $f :: $($_.Exception.Message)" "ERROR"
      if (-not $ContinueOnError) { throw }
    }
  }

  Write-Log "State saved: $StateFile" "OK"
  Write-Log "==== Completed successfully. Log: $LogFile ====" "OK"
  exit 0
}
catch {
  Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
  Write-Log "Log file: $LogFile" "ERROR"
  exit 1
}
