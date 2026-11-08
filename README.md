# KernelReaper

Kernel-level EDR evasion toolkit for authorized penetration testing. Uses RootLaser.sys (KDU Provider 65), a WHQL-signed driver, to perform direct kernel memory read/write operations for bypassing endpoint security protections.

## Modules

| Module | Switch | Description |
|--------|--------|-------------|
| **PPL Removal** | `-RemovePPL` | Removes RunAsPPL protection from lsass.exe by zeroing EPROCESS SignatureLevel, SectionSignatureLevel and Protection fields |
| **Callback Removal** | `-Callbacks` | Enumerates and removes kernel notification callbacks (PsSetCreateProcessNotifyRoutine, PsSetCreateThreadNotifyRoutine, PsSetLoadImageNotifyRoutine, CmRegisterCallback, ObRegisterCallbacks) registered by EDR drivers |
| **ETW Blind** | `-ETWBlind` | Disables kernel ETW Threat Intelligence provider to prevent telemetry collection |
| **Token Downgrade** | `-TokenDowngrade` | Strips privileges from EDR process tokens (SeDebugPrivilege, etc.) |
| **EDR Kill** | `-EDRKill` | Terminates EDR processes after stripping their kernel protections (PPL, callbacks, object callbacks) |

## Requirements

- Windows x64 (tested on Win10 22H2, Win11 24H2, Server 2008 SP2, Server 2016, Server 2022)
- Administrator privileges
- Test signing enabled (`bcdedit /set testsigning on`) or equivalent driver loading method
- `drv64.dll` from KDU (included)

## Usage

```powershell
# Run as Administrator

# Remove PPL from lsass only
.\Invoke-KernelReaper.ps1 -RemovePPL

# Remove EDR kernel callbacks (dry run - read only, no modifications)
.\Invoke-KernelReaper.ps1 -CallbacksDryRun

# Remove EDR kernel callbacks (live)
.\Invoke-KernelReaper.ps1 -Callbacks

# Blind ETW Threat Intelligence
.\Invoke-KernelReaper.ps1 -ETWBlind

# Downgrade EDR process tokens
.\Invoke-KernelReaper.ps1 -TokenDowngrade

# Kill EDR processes (strips protections then terminates)
.\Invoke-KernelReaper.ps1 -EDRKill

# Kill EDR processes in loop for 5 minutes (re-kills on respawn)
.\Invoke-KernelReaper.ps1 -EDRKill -KillDuration 300

# Run all modules
.\Invoke-KernelReaper.ps1 -All

# Target specific EDR processes
.\Invoke-KernelReaper.ps1 -EDRKill -TargetEDR "MsMpEng.exe,CrowdStrike.exe"

# Target specific PIDs
.\Invoke-KernelReaper.ps1 -EDRKill -TargetPID 1234,5678

# Enable debug logging
.\Invoke-KernelReaper.ps1 -All -DebugLog "C:\temp\debug.log"

# Use a custom driver path
.\Invoke-KernelReaper.ps1 -RemovePPL -Drv64Path "C:\tools\drv64.dll"
```

## Supported OS versions

| OS | Build | PPL | Callbacks | ETW Blind | Token | EDR Kill |
|----|-------|-----|-----------|-----------|-------|----------|
| Windows 11 24H2 | 26100 | Yes | Yes | Yes* | Yes | Yes |
| Windows 10 22H2 | 19045 | Yes | Yes | Yes* | Yes | Yes |
| Windows Server 2022 | 20348 | Yes | Yes | Yes* | Yes | Yes |
| Windows Server 2016 | 14393 | Yes | Yes | Yes* | Yes | Yes |
| Windows 8.1 | 9600 | Yes | Yes | Yes* | Yes | Yes |
| Windows 8 | 9200 | N/A | Yes | Yes* | Yes | Yes |
| Windows 7 SP1 | 7601 | N/A | Yes | N/A | Yes | Yes |
| Server 2008 SP2 | 6003 | N/A | Yes | N/A | Yes | Yes |

\* ETW Blind uses targeted scanning for the TI provider GUID. If the provider is not found, it returns gracefully without modification.

## How it works

1. Extracts RootLaser.sys (KDU Provider 65) from `drv64.dll` - a WHQL-signed driver with kernel read/write IOCTLs
2. Installs the driver as a kernel service
3. Uses the driver's IOCTLs to read/write arbitrary kernel virtual addresses
4. Locates EPROCESS structures via PsInitialSystemProcess and ActiveProcessLinks traversal
5. Modifies kernel structures (protection levels, callback arrays, ETW providers, tokens) depending on selected modules
6. Unloads the driver and cleans up on exit

## Built-in EDR target list

The default target list covers major EDR vendors:

- **Microsoft Defender**: MsMpEng, MsSense, SenseIR, SenseCncProxy
- **CrowdStrike**: CrowdStrike, CSFalconService, CSFalconContainer
- **Carbon Black**: cb, CbDefense, CbOsR, RepMgr
- **SentinelOne**: SentinelOne, SentinelAgent, SentinelServiceHost
- **Cylance**: CylanceSvc, CylanceUI
- **Trellix/FireEye**: xagt, xagtnotif
- **Tanium**: TaniumClient, TaniumCX
- **Palo Alto**: Traps, CyvrFsFlt, cyserver
- **Webroot**: WRSA, WRCoreService
- **Bitdefender**: bdservicehost, bdagent, bdntwrk
- **Sophos**: savservice, SophosAgent, SophosCleanM
- **Kaspersky**: klif, kavfs, avp
- **F-Secure**: fshoster32, FSSOMA
- **ESET**: ERAAgent, ekrn, egui
- **Fortinet**: fortitray, FortiESNAC, FCDBLog

## Disclaimer

**This tool is provided for authorized penetration testing and security research purposes only.**

Usage of this tool against systems without explicit written authorization is illegal. The author assumes no liability for misuse or damage caused by this tool. It is the end user's responsibility to comply with all applicable local, state, federal, and international laws.

This tool is intended to be used by professional penetration testers and security researchers during authorized engagements only.

## License

See [LICENSE](LICENSE) file.
