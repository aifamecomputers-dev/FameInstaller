# FameInstaller

PowerShell-based installer + uninstaller for two organizations:

- **Amax**: https://file.famepbx.com/amax/
- **Alpa**: https://file.famepbx.com/alpa/

The installer downloads and installs the full contents of the selected org folder, with **.NET installed first**, then the remaining installers.

> **Latest installer script:** `install_v1.ps1`  
> **Uninstaller:** `uninstall.ps1`

---

## Requirements

- Windows 11 (works on Windows 10 too in most cases)
- Run as **Administrator** (the scripts can self-elevate, but admin is required for installs/uninstalls)
- Internet access to download installers from the Fame file server

---

## Quick Start (recommended)

### Download scripts
Open PowerShell and run:

```powershell
$repo = "https://raw.githubusercontent.com/aifamecomputers-dev/FameInstaller/main"
$dir  = "$env:USERPROFILE\Downloads\FameInstaller"

New-Item -ItemType Directory -Force -Path $dir | Out-Null
Invoke-WebRequest "$repo/install_v1.ps1" -OutFile "$dir\install_v1.ps1" -UseBasicParsing
Invoke-WebRequest "$repo/uninstall.ps1"  -OutFile "$dir\uninstall.ps1"  -UseBasicParsing

```Command to Run:
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;iwr ('https://raw.githubusercontent.com/aifamecomputers-dev/FameInstaller/main/install_v1.ps1?nocache='+[guid]::NewGuid()) -OutFile $env:TEMP\install_v1.ps1;Unblock-File $env:TEMP\install_v1.ps1;Start-Process powershell -Verb RunAs -ArgumentList '-ExecutionPolicy Bypass -File "$env:TEMP\install_v1.ps1" -Org Amax -ContinueOnError '"
