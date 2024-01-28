@echo off
title Nebula Panel
:Menu
SETLOCAL EnableExtensions DisableDelayedExpansion
for /F %%a in ('echo prompt $E ^| cmd') do (
  set "ESC=%%a"
)
SETLOCAL EnableDelayedExpansion
chcp 65001
mode 61,16
cls
:::  !ESC![95m _   _      _           _         _____                 _ !ESC![0m
:::  !ESC![95m| \ | |    | |         | |       |  __ \               | |!ESC![0m
:::  !ESC![95m|  \| | ___| |__  _   _| | __ _  | |__) |_ _ _ __   ___| |!ESC![0m
:::  !ESC![95m| . ` |/ _ \ '_ \| | | | |/ _` | |  ___/ _` | '_ \ / _ \ |!ESC![0m
:::  !ESC![95m| |\  |  __/ |_) | |_| | | (_| | | |  | (_| | | | |  __/ |!ESC![0m
:::  !ESC![95m|_| \_|\___|_.__/ \__,_|_|\__,_| |_|   \__,_|_| |_|\___|_|!ESC![0m
for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A
echo.          !ESC![4mSelect the option that you would like to use!ESC![0m
echo.
echo.     !ESC![95m╔═════════════════════════════════════════════════╗!ESC![0m
echo.      !ESC![35m█!ESC![0m───────────────────!ESC![35m█!ESC![0m──────────────!ESC![35m█!ESC![0m────────────!ESC![35m█!ESC![0m
echo.      !ESC![35m█!ESC![0m !ESC![35m[1]!ESC![0m Optimizations !ESC![35m█!ESC![0m !ESC![35m[2]!ESC![0m Programs !ESC![35m█!ESC![0m !ESC![35m[3]!ESC![0m Others !ESC![35m█!ESC![0m
echo.      !ESC![35m█!ESC![0m───────────────────!ESC![35m█!ESC![0m──────────────!ESC![35m█!ESC![0m────────────!ESC![35m█!ESC![0m
echo.     !ESC![95m╚═════════════════════════════════════════════════╝!ESC![0m
set /p Options= !ESC![35m/!ESC![0m
if %Options% equ 1 goto Optimizations
if %Options% equ 2 goto Programs
if %Options% equ 3 goto Discord

:Programs
SETLOCAL EnableExtensions DisableDelayedExpansion
for /F %%a in ('echo prompt $E ^| cmd') do (
  set "ESC=%%a"
)
SETLOCAL EnableDelayedExpansion
chcp 65001
mode 61,31
cls
for /f "delims=: tokens=*" %%A in ('findstr /b :: "%~f0"') do @echo(%%A
echo.          !ESC![4mSelect the option that you would like to use!ESC![0m
echo.
echo.
echo.                        !ESC![4mInstall Browser!ESC![0m
echo.       !ESC![95m╔═══════════════════════════════════════════════╗!ESC![0m
echo.        !ESC![35m█!ESC![0m─────────────────────!ESC![35m█!ESC![0m───────────────────────!ESC![35m█!ESC![0m
echo.        !ESC![35m█!ESC![0m !ESC![35m[1]!ESC![0m Thorium Browser !ESC![35m█!ESC![0m !ESC![35m[2]!ESC![0m Librewolf Browser !ESC![35m█!ESC![0m
echo.        !ESC![35m█!ESC![0m─────────────────────!ESC![35m█!ESC![0m───────────────────────!ESC![35m█!ESC![0m
echo.       !ESC![95m╚═══════════════════════════════════════════════╝!ESC![0m
echo.
echo.
echo.                    !ESC![4mInstall Misc Programs!ESC![0m
echo.             !ESC![95m╔═══════════════════════════════╗!ESC![0m
echo.              !ESC![35m█!ESC![0m──────────────!ESC![35m█!ESC![0m──────────────!ESC![35m█!ESC![0m
echo.              !ESC![35m█!ESC![0m !ESC![35m[3]!ESC![0m Affinity !ESC![35m█!ESC![0m !ESC![35m[4]!ESC![0m MSI Util !ESC![35m█!ESC![0m
echo.              !ESC![35m█!ESC![0m──────────────!ESC![35m█!ESC![0m──────────────!ESC![35m█!ESC![0m
echo.             !ESC![95m╚═══════════════════════════════╝!ESC![0m
echo.            !ESC![95m╔═════════════════════════════════╗!ESC![0m
echo.             !ESC![35m█!ESC![0m──────────────!ESC![35m█!ESC![0m────────────────!ESC![35m█!ESC![0m
echo.             !ESC![35m█!ESC![0m !ESC![35m[5]!ESC![0m AutoRuns !ESC![35m█!ESC![0m !ESC![35m[6]!ESC![0m DevCleanup !ESC![35m█!ESC![0m
echo.             !ESC![35m█!ESC![0m──────────────!ESC![35m█!ESC![0m────────────────!ESC![35m█!ESC![0m
echo.            !ESC![95m╚═════════════════════════════════╝!ESC![0m
set /p Programs= !ESC![35m/!ESC![0m
if %Programs% equ 1 goto th
if %Programs% equ 2 goto lw
if %Programs% equ 3 goto af
if %Programs% equ 4 goto msi
if %Programs% equ 5 goto ar
if %Programs% equ 6 goto devcl

:th
curl -g -k -L -# -o "C:\Windows\Temp\Thorium.exe" "https://github.com/Alex313031/Thorium-Win-AVX2/releases/latest/download/thorium_AVX2_mini_installer.exe" >NUL 2>&1 & powershell Start-Process -FilePath "C:\Windows\Temp\Thorium.exe /S" >NUL 2>&1
goto Menu

:lw
curl -g -k -L -# -o "C:\Windows\Temp\Librewolf.exe" "https://gitlab.com/api/v4/projects/44042130/packages/generic/librewolf/122.0-1/librewolf-122.0-1-windows-x86_64-setup.exe" >NUL 2>&1 & powershell Start-Process -FilePath "C:\Windows\Temp\Librewolf.exe" >NUL 2>&1
goto Menu

:af
curl -g -k -L -# -o "C:\Windows\Temp\Affinity.exe" "https://github.com/Team-Nebula-Inc/neubla-panel/raw/main/programs/affinity.exe" >NUL 2>&1 & powershell Start-Process -FilePath "C:\Windows\Temp\Affinity.exe" >NUL 2>&1
goto Menu

:msi
curl -g -k -L -# -o "C:\Windows\Temp\MSI.exe" "https://github.com/Team-Nebula-Inc/neubla-panel/raw/main/programs/msi.exe" >NUL 2>&1 & powershell Start-Process -FilePath "C:\Windows\Temp\MSI.exe" >NUL 2>&1
goto Menu

:ar
curl -g -k -L -# -o "C:\Windows\Temp\Autoruns.exe" "https://github.com/Team-Nebula-Inc/neubla-panel/raw/main/programs/Autoruns.exe" >NUL 2>&1 & powershell Start-Process -FilePath "C:\Windows\Temp\Autoruns.exe" >NUL 2>&1
goto Menu

:devcl
curl -g -k -L -# -o "C:\Windows\Temp\DeviceCleanup.exe" "https://github.com/Team-Nebula-Inc/neubla-panel/raw/main/programs/DeviceCleanup.exe" >NUL 2>&1 & powershell Start-Process -FilePath "C:\Windows\Temp\DeviceCleanup.exe" >NUL 2>&1
goto Menu

:Discord
start https://discord.gg/sTHTA56H5B

:Optimizations
setlocal

for /f "tokens=2 delims==" %%a in ('wmic path Win32_VideoController get VideoProcessor /value') do (
    for %%n in (GeForce NVIDIA RTX GTX) do echo %%a | find "%%n" >nul && set "NVIDIAGPU=Found"
    for %%n in (AMD Ryzen) do echo %%a | find "%%n" >nul && set "AMDGPU=Found"
    for %%n in (Intel UHD) do echo %%a | find "%%n" >nul && set "INTELGPU=Found"
    for %%n in (Virtual) do echo %%a | find "%%n" >nul && set "VM=Found"
)

if defined NVIDIAGPU (
    goto Green
) else if defined AMDGPU (
    goto Red
) else if defined INTELGPU (
    goto Nebula
) else if defined VM (
    goto Nebula
) else (
    goto Nebula
)

endlocal

:Green
REM NVIDIA GPU
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PreferSystemMemoryContiguous /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v D3PCLatency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v F1TransitionLatency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LOWLATENCY /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v Node3DLowLatency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PciLatencyTimerControl /t REG_DWORD /d 32 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMDeepL1EntryLatencyUsec /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RmGspcMaxFtuS /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RmGspcMinFtuS /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RmGspcPerioduS /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrEiIdleThresholdUs /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrGrIdleThresholdUs /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrGrRgIdleThresholdUs /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v RMLpwrMsIdleThresholdUs /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v VRDirectFlipDPCDelayUs /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v VRDirectFlipTimingMarginUs /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v VRHwDirectFlipDPCDelayUs /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v VRHwDirectFlipTimingMarginUs /t REG_DWORD /d 1 /f >NUL 2>&1
goto Nebula

:Red
REM AMD GPU
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRSnoopL1Latency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRSnoopL0Latency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRNoSnoopL1Latency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v LTRMaxNoSnoopLatency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v KMD_RpmComputeLatency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DalUrgentLatencyNs /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v memClockSwitchLatency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PP_RTPMComputeF1Latency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PP_DGBMMMaxTransitionLatencyUvd /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v PP_DGBPMMaxTransitionLatencyGfx /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v DalNBLatencyForUnderFlow /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRSnoopL1Latency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRSnoopL0Latency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRNoSnoopL1Latency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRNoSnoopL0Latency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRMaxSnoopLatencyValue /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v BGM_LTRMaxNoSnoopLatencyValue /t REG_DWORD /d 1 /f >NUL 2>&1
goto Nebula

:Nebula

REM Linear Address 57
bcdedit /set linearaddress57 OptOut >NUL 2>&1
bcdedit /set increaseuserva 268435328 >NUL 2>&1

REM Contiguous Memory Optimization
bcdedit /set firstmegabytepolicy UseAll
bcdedit /set avoidlowmemory 0x8000000 >NUL 2>&1
bcdedit /set nolowmem Yes >NUL 2>&1

REM Disable Selective Kernel Mitigation
bcdedit /set allowedinmemorysettings 0x0 >NUL 2>&1
bcdedit /set isolatedcontext No >NUL 2>&1

REM Disable DMA Memory Protection & Cores Isolation
bcdedit /set vsmlaunchtype Off >NUL 2>&1
bcdedit /set vm No >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FVE" /v DisableExternalDMAUnderLock /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v HVCIMATRequired /t REG_DWORD /d 0 /f >NUL 2>&1

REM Disable Process and Kernel Mitigations
powershell -command "ForEach($v in (Get-Command -Name \"Set-ProcessMitigation\").Parameters[\"Disable\"].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}" >NUL 2>&1
powershell -command "Remove-Item -Path \"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\" -Recurse -ErrorAction SilentlyContinue" >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v DisableExceptionChainValidation /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v KernelSEHOPEnabled /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v EnableCfg /t REG_DWORD /d 0 /f >NUL 2>&1

REM Realtime Priority for csrss.exe
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v CpuPriorityClass /t REG_DWORD /d 4 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csrss.exe\PerfOptions" /v IoPriority /t REG_DWORD /d 3 /f >NUL 2>&1

REM Disable RAM compression
powershell -command "Disable-MMAgent -MemoryCompression" >NUL 2>&1

REM Enable Kernel-Managed Memory & Disable Meltdown/Spectre Patches
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettings /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f >NUL 2>&1

REM Disallow drivers to get paged into virtual memory
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v DisablePagingExecutive /t REG_DWORD /d 1 /f >NUL 2>&1

REM Use big system memory caching to improve microstuttering
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v LargeSystemCache /t REG_DWORD /d 1 /f >NUL 2>&1

REM Large Pagefile Utilization for Improved Microstuttering Reduction (Potential System Instability and BSoD Risk)
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False >NUL 2>&1
wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=32768,MaximumSize=32768 >NUL 2>&1

REM Disable additional NTFS/ReFS mitigations
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v ProtectionMode /t REG_DWORD /d 0 /f >NUL 2>&1

REM Enable X2Apic and enable Memory Mapping for PCI-E devices (Enable MSI Mode for all devices using MSI utility or manually for best results)
bcdedit /set x2apicpolicy Enable >NUL 2>&1
bcdedit /set configaccesspolicy Default >NUL 2>&1
bcdedit /set MSI Default >NUL 2>&1
bcdedit /set usephysicaldestination No >NUL 2>&1
bcdedit /set usefirmwarepcisettings No >NUL 2>&1

REM Accurate RTC for Synthetic TSC Tick Disabling (Recommended with HPET Enablement in BIOS for Untweaked Systems)
bcdedit /deletevalue useplatformclock >NUL 2>&1
bcdedit /deletevalue disabledynamictick >NUL 2>&1
bcdedit /set useplatformtick Yes >NUL 2>&1
bcdedit /set tscsyncpolicy Enhanced >NUL 2>&1

REM Set a reliable 1 ms (minimum) timestamp. Only for untweaked systems (disabling it with 0 is recommended on tweaked systems)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Reliability" /v TimeStampInterval /t REG_DWORD /d 1 /f >NUL 2>&1

REM Force contiguous memory allocation in the DirectX Graphics Kernel
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v DpiMapIommuContiguous /t REG_DWORD /d 1 /f >NUL 2>&1

REM Enforce Security-Only Telemetry (disable other kinds of Telemetry)
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >NUL 2>&1

REM Disable Application Telemetry
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f >NUL 2>&1

REM Disable Windows Error Reporting
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v LoggingEnabled /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows NT\Terminal Services" /v LoggingEnabled /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Error Reporting" /v LoggingDisabled /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v LoggingDisabled /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v DontSendAdditionalData /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DoReport" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >NUL 2>&1

REM Enable Experimental Autotuning and NEWRENO congestion provider
netsh int tcp set supp internet congestionprovider=newreno >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\QoS" /v Tcp Autotuning Level /t REG_DWORD /d Experimental /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\QoS" /v Application DSCP Marking Request /t REG_DWORD /d Allowed /f >NUL 2>&1

REM Enable WH send and WH receive
powershell -Command "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue" >NUL 2>&1

REM Enable UDP offloading
netsh int udp set global uro=enabled >NUL 2>&1

REM Enable Teredo and 6to4 (Win 2004 Xbox LIVE fix)
netsh int teredo set state natawareclient >NUL 2>&1
netsh int 6to4 set state state=enabled >NUL 2>&1

REM Tell Windows to stop tolerating high DPC/ISR latencies
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v ExitLatencyCheckEnabled /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v Latency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceDefault /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceFSVP /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyTolerancePerfOverride /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceScreenOffIR /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v LatencyToleranceVSyncEnabled /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power" /v RtlCapabilityCheckLatency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyActivelyUsed /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleLongTime /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleMonitorOff /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleNoContext /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleShortTime /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultD3TransitionLatencyIdleVeryLongTime /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle0 /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle0MonitorOff /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle1 /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceIdle1MonitorOff /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceMemory /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceNoContext /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceNoContextMonitorOff /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceOther /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultLatencyToleranceTimerPeriod /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultMemoryRefreshLatencyToleranceActivelyUsed /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultMemoryRefreshLatencyToleranceMonitorOff /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v DefaultMemoryRefreshLatencyToleranceNoContext /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v Latency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MaxIAverageGraphicsLatencyInOneBucket /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MiracastPerfTrackGraphicsLatency /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MonitorLatencyTolerance /t REG_DWORD /d 1 /f >NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Power" /v MonitorRefreshLatencyTolerance /t REG_DWORD /d 1 /f >NUL 2>&1

REM Disabling Windows Sync
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\PackageState" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableAppSyncSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SettingSync" /v DisableAppSyncSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableAppSyncSettingSyncUserOverride /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SettingSync" /v DisableAppSyncSettingSyncUserOverride /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSyncUserOverride /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SettingSync" /v DisableApplicationSettingSyncUserOverride /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWebBrowserSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SettingSync" /v DisableWebBrowserSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWebBrowserSettingSyncUserOverride /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SettingSync" /v DisableWebBrowserSettingSyncUserOverride /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableDesktopThemeSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SettingSync" /v DisableDesktopThemeSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableDesktopThemeSettingSyncUserOverride /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SettingSync" /v DisableDesktopThemeSettingSyncUserOverride /t REG_DWORD /d 0 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWindowsSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\SettingSync" /v DisableWindowsSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v DisableWindowsSettingSyncUserOverride /t REG_DWORD /d 0 /f >NUL 2>&1

REM Disable Prefetcher and Superfetch
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f >NUL 2>&1
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f >NUL 2>&1

REM Win32PrioritySeparation
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "38" /f >NUL 2>&1

REM Enable Gamemode
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "1" /f >NUL 2>&1
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "1" /f >NUL 2>&1
goto Menu
