# IPControl PowerShell module

> Requires an API account on an IPControl instance

![image](usage-example.png)

```
Created by AutomateNOW-Fan
```
```
⚠ Not affiliated with Cygna Labs
```
## Efficacy 🧪

Compatible with IPControl version 14.0 Build 48
<br/><br/>
## Installation 🏗

Install from the PowerShell Gallery 👉 `Install-Module -Name IPControl -Scope CurrentUser`
<br/><br/>
## Usage 🤔
Use `Connect-IPControl` to establish your session
<br/><br/>
## Features 🤓

- Completely browserless operation
- Both http & https protocols supported
- PowerShell Core (incl. Linux 🐧) & Windows PowerShell compatible
- PSScriptAnalyzer compliant / Approved verbs only
<br/><br/>
## Change Log 📝

## 1.0.1
### Major updates
- Fixed all issues with `Connect-IPControl`
- Added a Classes.psm1 file
- You can now retrieve Containers
- You can now retrieve Resource Records
- You can now delete Devices

### Minor updates
- It is now possible to fetch a Device by its IPControl Id or by its MAC address (if available)
- The expiration date of the current token is now checked whenever invoking the API

### Detailed Change Log
- New functions added: 'Complete-IPControlDeviceResourceRecordExport', 'Confirm-IPControlSession', 'Disconnect-IPControl', 'Get-IPControlContainer', 'Get-IPControlDeviceResourceRecord', 'Initialize-IPControlDeviceResourceRecordExport', 'Remove-IPControlDevice'
- Added the `-Hostname`, `-MACAddress` and `-Id` parameters to `Get-AutomateNOWDevice`
- Added pipeline capability to `Get-IPControlDevice`

## 1.0.0
### Major updates
- Initial release (Feedback welcomed)
