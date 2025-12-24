<#
Fame Folder Installer (Windows 11) - installs everything in org folder
Org folders:
  Alpa -> https://file.famepbx.com/alpa/
  Amax -> https://file.famepbx.com/amax/

Behavior:
- NetFx64.exe first
- Then all .msi (alphabetical)
- Then all remaining .exe (alphabetical)
- Skips folders + non-install files
- Waits if another install is running (msiexec)
- Uses installer-type detection for silent args (Inno/NSIS/InstallShield)
- Logs to C:\ProgramData\FameInstaller\logs

Run:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Org Amax
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet("Alpa","Amax")]
  [string]$Org,

  # If true, continues with next installers even if one fails
  [switch]$ContinueOnError,

  # If true, only downloads (no install)
  [switch]$DownloadOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ----------------------------
# Paths / Logging
# ----------------------------
$BaseRoot = "C:\ProgramData\FameInstaller"
$LogDir   = Join-Path $BaseRoot "logs"
$CacheDir = Join-Path $BaseRoot "cache\$Org"
New-Item -ItemType Directory -Force -Path $LogDir, $CacheDir | Out-Null

$Stamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = Join-Path $LogDir "install_$Org`_$Stamp.log"

function Write-Log {
  param([string]$Message, [ValidateSet("INFO","WARN","ERROR","OK")] [string]$Level="INFO")
  $line = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
  $line | Tee-Object -FilePath $LogFile -Append
}

# ----------------------------
# Elevation
# ----------------------------
function Ensure-Admin {
  $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

  if (-not $isAdmin) {
    Write-Log "Not running as Administrator. Re-launching elevated..." "WARN"
    $args = @(
      "-NoProfile","-ExecutionPolicy","Bypass",
      "-File", "`"$PSCommandPath`"",
      "-Org",$Org
    )
    if ($ContinueOnError) { $args += "-ContinueOnError" }
    if ($DownloadOnly)    { $args += "-DownloadOnly" }

    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs | Out-Null
    exit 0
  }
}

# ----------------------------
# Wait for other MSI installs
# ----------------------------
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

# ----------------------------
# Directory listing fetch
# ----------------------------
function Get-RemoteInstallFiles {
  param([Parameter(Mandatory=$true)][string]$BaseUrl)

  $basicUrl = if ($BaseUrl.EndsWith("/")) { "$BaseUrl?get=basic" } else { "$BaseUrl/?get=basic" }
  Write-Log "Fetching file list: $basicUrl"

  $html = (Invoke-WebRequest -Uri $basicUrl -UseBasicParsing).Content

  $hrefs = [regex]::Matches($html, 'href="([^"]+)"') | ForEach-Object { $_.Groups[1].Value }

  # Keep only .exe/.msi files (skip folders, configs, parent)
  $files = $hrefs |
    Where-Object { $_ -and ($_ -match '\.(exe|msi)$') } |
    ForEach-Object { [System.Uri]::UnescapeDataString($_) } |
    Where-Object {
      $_ -notmatch '(^\.\.$)' -and
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

# ----------------------------
# Download
# ----------------------------
function Download-File {
  param([Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutPath,
        [int]$Retries = 4)

  if (Test-Path $OutPath) {
    Write-Log "Cache hit: $OutPath"
    return
  }

  for ($i=1; $i -le $Retries; $i++) {
    try {
      Write-Log "Downloading ($i/$Retries): $Url"
      Invoke-WebRequest -Uri $Url -OutFile $OutPath -UseBasicParsing -Headers @{ "Cache-Control"="no-cache" }
      if (-not (Test-Path $OutPath)) { throw "Download failed (file not created)." }
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
# Installer type detection (improves silent accuracy)
# ----------------------------
function Get-InstallerSignature {
  param([Parameter(Mandatory=$true)][string]$ExePath)

  # Read first ~8MB (fast + enough for signatures)
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

  # File-specific overrides (best accuracy)
  if ($FileName -match '^NetFx64\.exe$') {
    return @("/q /norestart", "/quiet /norestart")
  }
  if ($FileName -match '^Reader_.*\.exe$' -or $FileName -match '^Reader_en_install') {
    # Adobe Reader style (common)
    return @("/sAll /rs /rps /msi EULA_ACCEPT=YES", "/quiet /norestart", "/S")
  }
  if ($FileName -match '^Splashtop_Streamer_.*\.exe$') {
    return @("/quiet /norestart", "/silent", "/S", "/verysilent /norestart")
  }

  # Signature-driven defaults
  switch ($Signature) {
    "INNO" { return @("/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-", "/SILENT /NORESTART /SP-") }
    "NSIS" { return @("/S") }
    "IS"   { return @("/s /v`"/qn /norestart`"", "/s") }
    "WIX"  { return @("/quiet /norestart", "/q") }
    default {
      # Controlled safe guesses (last resort)
      return @(
        "/quiet /norestart",
        "/q /norestart",
        "/S",
        "/silent",
        "/verysilent /norestart",
        "/s /v`"/qn /norestart`""
      )
    }
  }
}

# ----------------------------
# Install runners
# ----------------------------
function Invoke-MsiInstall {
  param([Parameter(Mandatory=$true)][string]$Path)
  Wait-For-InstallerIdle
  $args = "/i `"$Path`" /qn /norestart"
  Write-Log "MSI: msiexec.exe $args"
  if ($DownloadOnly) { Write-Log "DownloadOnly: skipping execution" "WARN"; return 0 }
  $p = Start-Process -FilePath "msiexec.exe" -ArgumentList $args -Wait -PassThru
  return $p.ExitCode
}

function Invoke-ExeInstall {
  param([Parameter(Mandatory=$true)][string]$Path)
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

      # Acceptable success codes
      if ($code -eq 0 -or $code -eq 3010) { return $code }

      # Another install in progress
      if ($code -eq 1618) {
        Write-Log "Exit 1618 (another install in progress). Waiting then retrying..." "WARN"
        Wait-For-InstallerIdle -MaxMinutes 45
        continue
      }

      # Common "already installed" style codes (best-effort treat as OK)
      if ($code -eq 1638) {
        Write-Log "Exit 1638 (another version already installed). Treating as OK." "WARN"
        return 0
      }

      Write-Log "Attempt failed: exit=$code (args=$a)" "WARN"
    } catch {
      Write-Log "Attempt exception: $($_.Exception.Message) (args=$a)" "WARN"
    }
  }

  throw "All silent install attempts failed for: $fileName. May require vendor-specific silent args."
}

# ----------------------------
# MAIN
# ----------------------------
try {
  Ensure-Admin
  Write-Log "==== Fame Folder Installer start | Org=$Org | Host=$env:COMPUTERNAME ===="

  $baseUrl = if ($Org -eq "Alpa") { "https://file.famepbx.com/alpa/" } else { "https://file.famepbx.com/amax/" }

  $files = Get-RemoteInstallFiles -BaseUrl $baseUrl

  # Order:
  # 1) NetFx64.exe
  # 2) all MSI (alpha)
  # 3) all other EXE (alpha)
  $dotnet = $files | Where-Object { $_ -ieq "NetFx64.exe" }
  $msis   = $files | Where-Object { $_ -match '\.msi$' } | Sort-Object
  $exes   = $files | Where-Object { $_ -match '\.exe$' -and $_ -ine "NetFx64.exe" } | Sort-Object

  $plan = @()
  if ($dotnet) { $plan += $dotnet }
  $plan += $msis
  $plan += $exes

  Write-Log ("Install plan ({0} items): {1}" -f $plan.Count, ($plan -join ", "))

  foreach ($f in $plan) {
    try {
      $url = $baseUrl.TrimEnd("/") + "/" + [uri]::EscapeDataString($f).Replace("+","%20")
      $local = Join-Path $CacheDir $f

      Download-File -Url $url -OutPath $local

      if ($f -match '\.msi$') {
        $exit = Invoke-MsiInstall -Path $local
      } else {
        $exit = Invoke-ExeInstall -Path $local
      }

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

  Write-Log "==== Completed successfully. Log: $LogFile ====" "OK"
  exit 0
}
catch {
  Write-Log "FATAL: $($_.Exception.Message)" "ERROR"
  Write-Log "Log file: $LogFile" "ERROR"
  exit 1
}
