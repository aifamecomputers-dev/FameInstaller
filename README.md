```Command to Run:
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;iwr ('https://raw.githubusercontent.com/aifamecomputers-dev/FameInstaller/main/install_v2.ps1?nocache='+[guid]::NewGuid()) -OutFile $env:TEMP\install_v2.ps1;Unblock-File $env:TEMP\install_v2.ps1;Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File "$env:TEMP\install_v2.ps1" -Org Alpa -ContinueOnError '"


# FameInstaller - PowerShell Installation Script

A robust, enterprise-grade PowerShell installer for distributing and managing software packages across multiple organizations with built-in Hairpin NAT detection, SSL certificate handling, and automatic reboot recovery.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Parameters](#parameters)
- [Hairpin NAT Issue & Solution](#hairpin-nat-issue--solution)
- [State & Tracking](#state--tracking)
- [Scheduled Task Auto-Resume](#scheduled-task-auto-resume)
- [Troubleshooting](#troubleshooting)
- [Logging](#logging)

## Overview

**FameInstaller** (`install_v1.ps1` / `install_v2.ps1`) is a PowerShell-based installer that:

- Automatically fetches and installs all packages (EXE/MSI) from a remote server
- Intelligently prioritizes installation order (NetFx64 → MSIs → EXEs)
- Detects and fixes Hairpin NAT issues for local network deployments
- Validates downloaded packages and re-downloads if corrupted
- Tracks installation history and exit codes in JSON state files
- Handles reboot-required scenarios with automatic task scheduling
- Supports both silent and UI-based installers
- Provides comprehensive logging for audit trails

## Features

### 🔒 Security & Validation
- TLS 1.2 enforced for all HTTPS connections
- HTML/partial download detection and automatic re-download
- MSI signature validation using Windows Installer COM
- EXE installer signature detection (Inno Setup, NSIS, InstallShield, WiX)
- Administrator elevation check with automatic re-launch

### 🌐 Network Resilience
- **Hairpin NAT Detection**: Automatically detects when the file server resolves to a local network IP
- **Automatic SSL Bypass**: Bypasses certificate validation when using local IP (since certificate is issued for domain)
- **DNS Resolution Logging**: Logs detected local IPs for troubleshooting
- **Override Support**: Manual base URL override for air-gapped or special network environments

### 📦 Installation Management
- **Smart Ordering**: NetFx64 first (if present), then MSIs, then other EXEs
- **Conflict Detection**: Detects when another installer (msiexec) is running and waits
- **Exit Code Handling**: Properly handles reboot-required (3010, 1641) and already-installed (1638) codes
- **Retry Logic**: Built-in retry mechanism for failed downloads (configurable)

### 🔄 State & Recovery
- Single-run lock to prevent parallel installations
- Persistent JSON state tracking in `C:\ProgramData\FameInstaller\state\<Org>\`
- Automatic scheduled task for post-reboot resumption
- Failed installation tracking with timestamps and error messages
- Uninstall registry entry tracking

### 📋 UI Support
- Designates specific installers as UI-required (e.g., Adobe Reader, PP14Downloader)
- Waits for user interaction without timeout
- Logs user's exit code for audit purposes

## Requirements

- **OS**: Windows 7 SP1 or later (Windows 10/11 recommended)
- **PowerShell**: Windows PowerShell 5.1 or later (no ternary operators, no null-conditional syntax)
- **Admin Rights**: Must run as Administrator (script auto-elevates if needed)
- **Network**: HTTPS access to file server (`https://file.famepbx.com/`)
- **.NET Framework**: 3.5+ (for COM interop with MSI)
- **Permissions**: 
  - Write access to `C:\ProgramData\FameInstaller\`
  - Access to create Scheduled Tasks
  - Registry read access for uninstall tracking

## Installation

### Method 1: Direct Execution
```powershell
# Run as Administrator
.\install_v1.ps1 -Org Alpa
# or
.\install_v1.ps1 -Org Amax
```

### Method 2: Batch/Task Scheduler
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\path\to\install_v1.ps1" -Org Alpa
```

### Method 3: With Hairpin NAT Override (if detection fails)
```powershell
.\install_v1.ps1 -Org Alpa -BaseUrlOverride "https://192.168.50.10/alpa/"
```

## Usage

### Basic Usage

```powershell
# Install all packages for Alpa organization
.\install_v1.ps1 -Org Alpa

# Install all packages for Amax organization
.\install_v1.ps1 -Org Amax
```

### Advanced Usage

```powershell
# Download only (don't install)
.\install_v1.ps1 -Org Alpa -DownloadOnly

# Continue on errors (don't stop on first failure)
.\install_v1.ps1 -Org Alpa -ContinueOnError

# Override base URL for air-gapped networks
.\install_v1.ps1 -Org Alpa -BaseUrlOverride "https://internal-server.local/alpa/"

# Combine multiple options
.\install_v1.ps1 -Org Alpa -ContinueOnError -DownloadOnly
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Org` | String | ✓ Yes | Organization name: `Alpa` or `Amax` |
| `-BaseUrlOverride` | String | ✗ No | Override the file server URL (e.g., `https://192.168.50.10/alpa/`) |
| `-ContinueOnError` | Switch | ✗ No | Don't stop if an installer fails; continue with remaining packages |
| `-DownloadOnly` | Switch | ✗ No | Download packages to cache but don't execute installers |
| `-Resumed` | Switch | ✗ No | Internal flag; used by scheduled task after reboot (don't use manually) |

## Hairpin NAT Issue & Solution

### What is Hairpin NAT?

Hairpin NAT (also called "NAT Loopback") occurs when devices on the local LAN try to access a service using its **public IP address or domain name**, but the router cannot route traffic back to the local network. The router "hairpins" (reflects) the traffic back.

**Symptom**: Devices on the LAN cannot download files from `https://file.famepbx.com/` even though the server is on the same local network.

### How FameInstaller Fixes It

The script automatically:

1. **Detects** if the domain `file.famepbx.com` resolves to a local network IP address (same /24 subnet)
2. **Logs** the detection:
   ```
   [WARN] Hairpin NAT detected: file.famepbx.com resolves to local network IP 192.168.89.253
   ```
3. **Switches** to the local IP address:
   ```
   [OK] Using local IP to avoid Hairpin NAT: https://192.168.89.253/alpa/
   ```
4. **Bypasses SSL Certificate Validation** (since the certificate is issued for the domain, not the IP):
   ```
   [WARN] SSL certificate validation bypassed for local IP
   ```

### Manual Override

If automatic detection fails, manually specify the local IP:

```powershell
.\install_v1.ps1 -Org Alpa -BaseUrlOverride "https://192.168.89.253/alpa/"
```

### Network Architecture Example

```
┌─────────────────────────────────────────────┐
│         Internet                             │
│     file.famepbx.com (public domain)        │
│     Points to: 203.0.113.50 (public IP)     │
└────────────────────┬────────────────────────┘
                     │
              ┌──────▼──────┐
              │   Router    │
              │  NAT Device │
              └──────┬──────┘
                     │
        ┌────────────┼────────────┐
        │            │            │
   ┌────▼───┐  ┌────▼───┐  ┌────▼───┐
   │ Server │  │ Client1 │  │ Client2 │
   │ 192...1 │  │ 192...2 │  │ 192...3 │
   └────────┘  └────────┘  └────────┘
   (Local LAN - 192.168.89.0/24)

🔴 PROBLEM (without Hairpin NAT fix):
   Client1 → Router → Internet → Back to Router
   (Router doesn't route back to local network)

✅ SOLUTION (FameInstaller):
   Client1 → Detect → Use 192.168.89.1 → Server
   (Direct local connection, bypassing router)
```

## State & Tracking

### Directory Structure

```
C:\ProgramData\FameInstaller\
├── logs\
│   ├── install_Alpa_20260111_075047.log
│   └── install_Amax_20260110_143022.log
├── cache\
│   ├── Alpa\
│   │   ├── NetFx64.exe
│   │   ├── Package1.msi
│   │   └── App2.exe
│   └── Amax\
│       ├── App1.msi
│       └── Setup.exe
└── state\
    ├── Alpa\
    │   ├── installed.json
    │   ├── install.lock
    │   └── [Scheduled task for resume]
    └── Amax\
        ├── installed.json
        └── install.lock
```

### State File Format

**File**: `C:\ProgramData\FameInstaller\state\<Org>\installed.json`

```json
{
  "org": "Alpa",
  "created": "2026-01-11T07:50:47.1234567Z",
  "resumed": false,
  "status": "success",
  "lastStart": "2026-01-11T07:50:47.1234567Z",
  "lastUpdate": "2026-01-11T07:52:15.5678901Z",
  "completed": "2026-01-11T07:52:16.1234567Z",
  "items": [
    {
      "file": "NetFx64.exe",
      "local": "C:\\ProgramData\\FameInstaller\\cache\\Alpa\\NetFx64.exe",
      "type": "exe",
      "installedAt": "2026-01-11T07:50:52.0000000Z",
      "exitCode": 0,
      "uninstallEntries": []
    },
    {
      "file": "Package1.msi",
      "local": "C:\\ProgramData\\FameInstaller\\cache\\Alpa\\Package1.msi",
      "type": "msi",
      "installedAt": "2026-01-11T07:51:15.0000000Z",
      "exitCode": 0,
      "msiProductCode": "{12345678-1234-1234-1234-123456789012}",
      "uninstallEntries": [
        {
          "KeyName": "{12345678-1234-1234-1234-123456789012}",
          "DisplayName": "Package1",
          "DisplayVersion": "1.0.0",
          "Publisher": "Example Corp",
          "UninstallString": "...",
          "WindowsInstaller": 1
        }
      ]
    }
  ],
  "rebootRequestedAt": null
}
```

### Status Values

- `running`: Installation in progress
- `success`: All packages installed successfully
- `rebooting`: Waiting for system reboot
- `fatal`: Unrecoverable error occurred

## Scheduled Task Auto-Resume

### How It Works

When an installer exits with code `3010` or `1641` (reboot required), the script:

1. Creates a Scheduled Task: `FameInstaller-Resume-<Org>`
2. Sets trigger to "At Startup"
3. Schedules with SYSTEM privileges and RunLevel Highest
4. Initiates system reboot

After reboot, the task automatically:
- Launches the script with `-Resumed` flag
- Continues from where it left off
- Cleans up the scheduled task when done

### Manual Resume

If auto-resume fails, manually run:

```powershell
.\install_v1.ps1 -Org Alpa -Resumed
```

### View Scheduled Tasks

```powershell
Get-ScheduledTask -TaskName "FameInstaller-Resume-*"
```

### Remove Scheduled Task

```powershell
Unregister-ScheduledTask -TaskName "FameInstaller-Resume-Alpa" -Confirm:$false
```

## Troubleshooting

### Common Issues

#### 1. SSL/TLS Certificate Error

**Error**: `The underlying connection was closed: Could not establish trust relationship for the SSL/TLS secure channel.`

**Cause**: Using local IP but certificate is issued for domain.

**Solution**: 
- ✅ Script now auto-bypasses SSL validation for local IPs
- If still failing, check that `-BaseUrlOverride` uses `https://`, not `http://`

#### 2. Hairpin NAT Not Detected

**Symptom**: Script tries to use public domain instead of local IP.

**Solution**:
```powershell
# Manually override with local IP
.\install_v1.ps1 -Org Alpa -BaseUrlOverride "https://192.168.89.253/alpa/"
```

**To find local IP**:
```powershell
# On the file server
ipconfig | findstr /I "IPv4"
```

#### 3. No Installers Found

**Error**: `No .exe/.msi installers found at https://...`

**Causes**:
- File server at base URL has no packages
- HTML parsing failed (blocked/403/404 response)
- Wrong organization name

**Solution**:
```powershell
# Verify server is accessible
Invoke-WebRequest -Uri "https://file.famepbx.com/alpa/?get=basic" -UseBasicParsing

# Check base URL override if needed
.\install_v1.ps1 -Org Alpa -BaseUrlOverride "https://correct-server/alpa/"
```

#### 4. Lock File Already Exists

**Error**: `Another FameInstaller run seems active (PID=...)`

**Cause**: Previous installation didn't complete or crashed.

**Solution**:
```powershell
# Check lock file
Get-Content "C:\ProgramData\FameInstaller\state\Alpa\install.lock"

# Verify process is dead (wait 2+ hours or delete lock)
Remove-Item "C:\ProgramData\FameInstaller\state\Alpa\install.lock" -Force
```

#### 5. MSI Invalid/Unopenable

**Error**: `MSI invalid/unopenable (1620). Likely bad package or blocked download.`

**Cause**: Downloaded file is HTML (server returned error page).

**Solution**:
- Check file server is online
- Verify base URL is correct
- Clear cache and retry:
```powershell
Remove-Item "C:\ProgramData\FameInstaller\cache\Alpa\*" -Force -Recurse
.\install_v1.ps1 -Org Alpa
```

#### 6. Not Running as Administrator

**Error**: `Not running as Administrator. Re-launching elevated...`

**Info**: This is normal! Script auto-elevates. Just run it normally (no `sudo`).

#### 7. Installer Timeout

**Error**: `Timeout waiting for <installer>. Killing PID=...`

**Cause**: UI installer hung or waiting for user input.

**Solution**:
- NetFx64.exe timeout: 40 minutes
- Other installers: 25 minutes
- Check if SmartScreen is blocking (click "Run anyway")

### Debug Logging

**View current installation log**:
```powershell
Get-ChildItem "C:\ProgramData\FameInstaller\logs\" | Sort-Object -Descending | Select-Object -First 1
tail -f "C:\ProgramData\FameInstaller\logs\install_Alpa_*.log"
```

**Check state file**:
```powershell
Get-Content "C:\ProgramData\FameInstaller\state\Alpa\installed.json" | ConvertFrom-Json | Format-List
```

**Test Hairpin NAT detection**:
```powershell
[System.Net.Dns]::GetHostAddresses("file.famepbx.com")
```

## Logging

### Log Location

`C:\ProgramData\FameInstaller\logs\install_<Org>_<Timestamp>.log`

Example: `install_Alpa_20260111_075047.log`

### Log Format

```
[2026-01-11 07:50:47] [INFO] ==== Fame Folder Installer start | Org=Alpa | Host=ALPHAEULESS1 | Resumed=False ====
[2026-01-11 07:50:51] [WARN] Hairpin NAT detected: file.famepbx.com resolves to local network IP 192.168.89.253
[2026-01-11 07:50:51] [OK]   Using local IP to avoid Hairpin NAT: https://192.168.89.253/alpa/
[2026-01-11 07:50:51] [INFO] Fetching file list: https://192.168.89.253/alpa/?get=basic
[2026-01-11 07:50:52] [INFO] Download OK: C:\ProgramData\FameInstaller\cache\Alpa\NetFx64.exe
[2026-01-11 07:50:52] [INFO] MSI: msiexec.exe /i "..." /qn /norestart
[2026-01-11 07:51:15] [OK]   Installed OK: Package1.msi
[2026-01-11 07:52:16] [OK]   ==== Completed successfully. Log: C:\ProgramData\FameInstaller\logs\install_Alpa_20260111_075047.log ====
```

### Log Levels

- `[INFO]`: General information
- `[WARN]`: Warning (may need attention, but not fatal)
- `[OK]`: Success
- `[ERROR]`: Error (fatal or partial failure)

## Contributing

To report issues or suggest improvements, please include:

1. Organization name (`Alpa` or `Amax`)
2. Full log file from `C:\ProgramData\FameInstaller\logs\`
3. State file from `C:\ProgramData\FameInstaller\state\<Org>\installed.json`
4. Network diagram (if Hairpin NAT related)

## License

Internal use only.

## Support

For support, check:
1. The **Troubleshooting** section above
2. Log file at `C:\ProgramData\FameInstaller\logs\`
3. State file at `C:\ProgramData\FameInstaller\state\<Org>\installed.json`

---

**Last Updated**: January 11, 2026  
**Version**: 1.0 (install_v1.ps1 / install_v2.ps1)
