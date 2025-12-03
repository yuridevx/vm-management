#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configures Windows for continuous VM hosting with optimal settings.

.DESCRIPTION
    This script configures a Windows machine to be an optimal VM host by:
    - Enabling auto-login (optional)
    - Disabling sleep, hibernation, and display timeout
    - Setting high performance power plan with maximum settings
    - Marking all networks as private
    - Enabling file sharing and network discovery
    - Disabling automatic Windows Update restarts
    - Optimizing for continuous operation
    - Disabling fast startup (better for VM hosts)
    - Configuring additional VM host optimizations

.PARAMETER SkipAutoLogin
    Skip the auto-login configuration section

.PARAMETER NoRestart
    Don't prompt to restart at the end

.PARAMETER LogFile
    Path to save a transcript log of the configuration

.PARAMETER WhatIf
    Show what changes would be made without actually making them

.PARAMETER CreateRestorePoint
    Create a system restore point before making changes

.EXAMPLE
    .\Configure-VMHost.ps1
    Run with all configurations including auto-login

.EXAMPLE
    .\Configure-VMHost.ps1 -SkipAutoLogin -NoRestart
    Configure everything except auto-login and skip restart prompt

.EXAMPLE
    .\Configure-VMHost.ps1 -LogFile "C:\Logs\vmhost-config.log"
    Run configuration and save detailed log

.EXAMPLE
    .\Configure-VMHost.ps1 -CreateRestorePoint -LogFile "C:\Logs\vmhost-config.log"
    Create restore point, configure system, and log all actions
#>

[CmdletBinding()]
param(
    [switch]$SkipAutoLogin,
    [switch]$NoRestart,
    [string]$LogFile,
    [switch]$WhatIf,
    [switch]$CreateRestorePoint
)

# Error handling - continue on errors
$ErrorActionPreference = "Continue"

# Start transcript if log file specified
if ($LogFile) {
    try {
        $logDir = Split-Path $LogFile -Parent
        if ($logDir -and -not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }
        Start-Transcript -Path $LogFile -Force
        Write-Host "Logging to: $LogFile" -ForegroundColor Gray
    } catch {
        Write-Warning "Could not start transcript logging: $_"
    }
}

# Track success/failure of each configuration section
$script:ConfigResults = @{
    AutoLogin = $null
    SleepHibernation = $null
    PowerPlan = $null
    FastStartup = $null
    NetworkPrivate = $null
    FileSharing = $null
    WindowsUpdate = $null
    ScreenSaver = $null
    VirtualMemory = $null
    Defender = $null
    SystemSounds = $null
    Virtualization = $null
    Additional = $null
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VM Host Configuration Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
if ($WhatIf) {
    Write-Host "RUNNING IN WHATIF MODE - No changes will be made" -ForegroundColor Magenta
    Write-Host ""
}
Write-Host "This script will continue even if individual sections fail." -ForegroundColor Gray
Write-Host ""

# Function to log actions
function Write-Status {
    param([string]$Message, [string]$Status = "INFO")
    $color = switch ($Status) {
        "SUCCESS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        "INFO"    { "Cyan" }
        default { "White" }
    }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] " -NoNewline
    Write-Host "[$Status] " -ForegroundColor $color -NoNewline
    Write-Host $Message
}

# Function to safely execute registry operations
function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        $Value,
        [string]$Type = "DWord"
    )

    if ($WhatIf) {
        Write-Host "  [WhatIf] Would set registry: $Path\$Name = $Value" -ForegroundColor Magenta
        return $true
    }

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }

        if ($Type -eq "DWord") {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWord -ErrorAction Stop
        } else {
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -ErrorAction Stop
        }
        return $true
    } catch {
        Write-Status "Registry operation failed: $Path\$Name - $_" "ERROR"
        return $false
    }
}

# ============================================
# PRE-FLIGHT CHECKS
# ============================================
Write-Host "`n[Pre-Flight] System Checks..." -ForegroundColor Yellow

# Check if running as Administrator
try {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Status "Script must run as Administrator!" "ERROR"
        exit 1
    }
    Write-Status "Running with Administrator privileges" "SUCCESS"
} catch {
    Write-Status "Could not verify admin rights: $_" "WARNING"
}

# Check Windows version
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $osVersion = [System.Environment]::OSVersion.Version
    Write-Status "OS: $($osInfo.Caption) (Build $($osInfo.BuildNumber))" "INFO"

    if ($osVersion.Major -lt 10) {
        Write-Status "This script is optimized for Windows 10/11" "WARNING"
    }
} catch {
    Write-Status "Could not determine OS version" "WARNING"
}

# Check if running in a VM
try {
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($computerSystem.Model -match "Virtual|VMware|VirtualBox|Hyper-V") {
        Write-Status "WARNING: This appears to be a virtual machine. This script is designed for VM hosts." "WARNING"
        $continue = Read-Host "Continue anyway? (Y/N)"
        if ($continue -ne 'Y' -and $continue -ne 'y') {
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit 0
        }
    } else {
        Write-Status "Running on physical hardware (expected for VM host)" "SUCCESS"
    }
} catch {
    Write-Status "Could not determine if running in VM" "WARNING"
}

# Check for pending reboot
try {
    $pendingReboot = $false

    # Check Component Based Servicing
    if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $pendingReboot = $true
    }

    # Check Windows Update
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $pendingReboot = $true
    }

    if ($pendingReboot) {
        Write-Status "System has a pending reboot. Recommend rebooting before configuration." "WARNING"
        $continue = Read-Host "Continue anyway? (Y/N)"
        if ($continue -ne 'Y' -and $continue -ne 'y') {
            Write-Host "Exiting..." -ForegroundColor Yellow
            exit 0
        }
    } else {
        Write-Status "No pending reboots detected" "SUCCESS"
    }
} catch {
    Write-Status "Could not check for pending reboots" "WARNING"
}

Write-Host ""

# Create system restore point if requested
if ($CreateRestorePoint -and -not $WhatIf) {
    Write-Host "[Creating System Restore Point]..." -ForegroundColor Yellow
    try {
        # Enable System Restore on C: if not already enabled
        Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue

        # Create restore point
        Checkpoint-Computer -Description "Pre-VMHost Configuration" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
        Write-Status "System restore point created: 'Pre-VMHost Configuration'" "SUCCESS"
    } catch {
        Write-Status "Could not create restore point: $_" "WARNING"
        Write-Host "  You can manually create a restore point from System Properties" -ForegroundColor Gray
    }
    Write-Host ""
}

if (-not $WhatIf) {
    Write-Host "Press any key to begin configuration or Ctrl+C to cancel..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Write-Host ""
}

# ============================================
# 1. CONFIGURE AUTO-LOGIN
# ============================================
if ($SkipAutoLogin) {
    Write-Host "`n[1/13] Skipping Auto-Login (parameter specified)..." -ForegroundColor Gray
    $script:ConfigResults.AutoLogin = "SKIPPED"
} else {
    Write-Host "`n[1/13] Configuring Auto-Login..." -ForegroundColor Yellow

    try {
        if (-not $WhatIf) {
            $username = Read-Host "Enter username for auto-login (default: $env:USERNAME)"
            if ([string]::IsNullOrWhiteSpace($username)) {
                $username = $env:USERNAME
            }

            $password = Read-Host "Enter password for auto-login" -AsSecureString
            $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
            )
        } else {
            $username = $env:USERNAME
            $passwordPlain = "********"
            Write-Host "  [WhatIf] Would configure auto-login for: $username" -ForegroundColor Magenta
        }

        $success = $true
        $success = $success -and (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Value "1" -Type "String")
        $success = $success -and (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Value $username -Type "String")

        if (-not $WhatIf) {
            $success = $success -and (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Value $passwordPlain -Type "String")
        }

        if ($success) {
            Write-Status "Auto-login enabled for user: $username" "SUCCESS"
            $script:ConfigResults.AutoLogin = "SUCCESS"
        } else {
            Write-Status "Auto-login configuration partially failed" "WARNING"
            $script:ConfigResults.AutoLogin = "PARTIAL"
        }
    } catch {
        Write-Status "Failed to configure auto-login: $_" "ERROR"
        $script:ConfigResults.AutoLogin = "FAILED"
    }
}

# ============================================
# 2. DISABLE SLEEP AND HIBERNATION
# ============================================
Write-Host "`n[2/13] Disabling Sleep and Hibernation..." -ForegroundColor Yellow

$sleepSuccess = $true
try {
    # Disable hibernation completely
    $result = powercfg /hibernate off 2>&1
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null) {
        Write-Status "Hibernation disabled" "SUCCESS"
    } else {
        Write-Status "Failed to disable hibernation (exit code: $LASTEXITCODE)" "WARNING"
        $sleepSuccess = $false
    }
} catch {
    Write-Status "Error disabling hibernation: $_" "WARNING"
    $sleepSuccess = $false
}

try {
    # Disable hybrid sleep
    powercfg /change /hibernate-timeout-ac 0 2>&1 | Out-Null
    powercfg /change /hibernate-timeout-dc 0 2>&1 | Out-Null
    Write-Status "Hybrid sleep disabled" "SUCCESS"
} catch {
    Write-Status "Error disabling hybrid sleep: $_" "WARNING"
    $sleepSuccess = $false
}

$script:ConfigResults.SleepHibernation = if ($sleepSuccess) { "SUCCESS" } else { "PARTIAL" }

# ============================================
# 3. SET HIGH PERFORMANCE POWER PLAN
# ============================================
Write-Host "`n[3/13] Configuring High Performance Power Plan..." -ForegroundColor Yellow

$powerSuccess = 0
$powerTotal = 6

# Enable and set High Performance power plan
try {
    powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null) {
        Write-Status "High Performance power plan activated" "SUCCESS"
        $powerSuccess++
    } else {
        Write-Status "Could not activate High Performance plan (may not exist on this system)" "WARNING"
    }
} catch {
    Write-Status "Error setting power plan: $_" "WARNING"
}

# Set all timeouts to never (0)
try {
    powercfg /change monitor-timeout-ac 0 2>&1 | Out-Null
    powercfg /change monitor-timeout-dc 0 2>&1 | Out-Null
    powercfg /change disk-timeout-ac 0 2>&1 | Out-Null
    powercfg /change disk-timeout-dc 0 2>&1 | Out-Null
    powercfg /change standby-timeout-ac 0 2>&1 | Out-Null
    powercfg /change standby-timeout-dc 0 2>&1 | Out-Null
    Write-Status "All power timeouts set to never" "SUCCESS"
    $powerSuccess++
} catch {
    Write-Status "Error setting power timeouts: $_" "WARNING"
}

# Disable USB selective suspend
try {
    powercfg /setacvalueindex SCHEME_CURRENT 2a737abc-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>&1 | Out-Null
    powercfg /setdcvalueindex SCHEME_CURRENT 2a737abc-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>&1 | Out-Null
    Write-Status "USB selective suspend disabled" "SUCCESS"
    $powerSuccess++
} catch {
    Write-Status "Error disabling USB suspend: $_" "WARNING"
}

# Set PCI Express Link State Power Management to Off
try {
    powercfg /setacvalueindex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 2>&1 | Out-Null
    powercfg /setdcvalueindex SCHEME_CURRENT 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 2>&1 | Out-Null
    Write-Status "PCI Express power management disabled" "SUCCESS"
    $powerSuccess++
} catch {
    Write-Status "Error setting PCI Express power: $_" "WARNING"
}

# Set processor minimum and maximum state to 100%
try {
    powercfg /setacvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100 2>&1 | Out-Null
    powercfg /setdcvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 100 2>&1 | Out-Null
    powercfg /setacvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100 2>&1 | Out-Null
    powercfg /setdcvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 100 2>&1 | Out-Null
    Write-Status "Processor power management set to maximum performance" "SUCCESS"
    $powerSuccess++
} catch {
    Write-Status "Error setting processor power: $_" "WARNING"
}

# Apply settings
try {
    powercfg /setactive SCHEME_CURRENT 2>&1 | Out-Null
    $powerSuccess++
} catch {
    Write-Status "Error applying power settings: $_" "WARNING"
}

$script:ConfigResults.PowerPlan = if ($powerSuccess -ge $powerTotal) { "SUCCESS" } elseif ($powerSuccess -gt 0) { "PARTIAL" } else { "FAILED" }

# ============================================
# 4. DISABLE FAST STARTUP
# ============================================
Write-Host "`n[4/13] Disabling Fast Startup..." -ForegroundColor Yellow

if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0) {
    Write-Status "Fast Startup disabled (better for VM hosts)" "SUCCESS"
    $script:ConfigResults.FastStartup = "SUCCESS"
} else {
    Write-Status "Failed to disable fast startup" "WARNING"
    $script:ConfigResults.FastStartup = "FAILED"
}

# ============================================
# 5. MARK ALL NETWORKS AS PRIVATE
# ============================================
Write-Host "`n[5/13] Setting All Networks to Private..." -ForegroundColor Yellow

$networkSuccess = 0
$networkTotal = 0
try {
    $profiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue
    if ($profiles) {
        foreach ($profile in $profiles) {
            $networkTotal++
            try {
                Set-NetConnectionProfile -InterfaceIndex $profile.InterfaceIndex -NetworkCategory Private -ErrorAction Stop
                Write-Status "Network '$($profile.Name)' set to Private" "SUCCESS"
                $networkSuccess++
            } catch {
                Write-Status "Failed to set network '$($profile.Name)' to private: $_" "WARNING"
            }
        }
        $script:ConfigResults.NetworkPrivate = if ($networkSuccess -eq $networkTotal) { "SUCCESS" } elseif ($networkSuccess -gt 0) { "PARTIAL" } else { "FAILED" }
    } else {
        Write-Status "No network profiles found" "WARNING"
        $script:ConfigResults.NetworkPrivate = "SKIPPED"
    }
} catch {
    Write-Status "Error accessing network profiles: $_" "ERROR"
    $script:ConfigResults.NetworkPrivate = "FAILED"
}

# ============================================
# 6. ENABLE FILE SHARING AND NETWORK DISCOVERY
# ============================================
Write-Host "`n[6/13] Enabling File Sharing and Network Discovery..." -ForegroundColor Yellow

$sharingSuccess = 0
$sharingTotal = 4

# Enable Network Discovery
try {
    $result = netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes 2>&1
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null) {
        Write-Status "Network Discovery enabled" "SUCCESS"
        $sharingSuccess++
    } else {
        Write-Status "Failed to enable Network Discovery" "WARNING"
    }
} catch {
    Write-Status "Error enabling Network Discovery: $_" "WARNING"
}

# Enable File and Printer Sharing
try {
    $result = netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes 2>&1
    if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null) {
        Write-Status "File and Printer Sharing enabled" "SUCCESS"
        $sharingSuccess++
    } else {
        Write-Status "Failed to enable File and Printer Sharing" "WARNING"
    }
} catch {
    Write-Status "Error enabling File and Printer Sharing: $_" "WARNING"
}

# Ensure SMB2/3 is enabled
try {
    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction Stop -WarningAction SilentlyContinue
    Write-Status "SMB2/3 protocol enabled" "SUCCESS"
    $sharingSuccess++
} catch {
    Write-Status "Error enabling SMB2/3: $_" "WARNING"
}

# Enable insecure guest logons (for VM network shares)
if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 1) {
    Write-Status "Guest authentication enabled for network shares" "SUCCESS"
    $sharingSuccess++
} else {
    Write-Status "Failed to enable guest authentication" "WARNING"
}

$script:ConfigResults.FileSharing = if ($sharingSuccess -ge $sharingTotal) { "SUCCESS" } elseif ($sharingSuccess -gt 0) { "PARTIAL" } else { "FAILED" }

# ============================================
# 7. DISABLE WINDOWS UPDATE AUTO-RESTART
# ============================================
Write-Host "`n[7/13] Disabling Windows Update Automatic Restart..." -ForegroundColor Yellow

$updateSuccess = $true
$updateSuccess = $updateSuccess -and (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Value 1)
$updateSuccess = $updateSuccess -and (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value 3)

if ($updateSuccess) {
    Write-Status "Windows Update auto-restart disabled" "SUCCESS"
    $script:ConfigResults.WindowsUpdate = "SUCCESS"
} else {
    Write-Status "Failed to fully configure Windows Update settings" "WARNING"
    $script:ConfigResults.WindowsUpdate = "PARTIAL"
}

# ============================================
# 8. DISABLE SCREEN SAVER AND LOCK SCREEN
# ============================================
Write-Host "`n[8/13] Disabling Screen Saver and Lock Screen..." -ForegroundColor Yellow

$screenSuccess = 0
$screenTotal = 3

# Disable screen saver
if (Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Value "0" -Type "String") {
    $screenSuccess++
}
if (Set-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Value "0" -Type "String") {
    $screenSuccess++
}

if ($screenSuccess -eq 2) {
    Write-Status "Screen saver disabled" "SUCCESS"
}

# Disable lock screen timeout
if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Value 1) {
    Write-Status "Lock screen disabled" "SUCCESS"
    $screenSuccess++
}

$script:ConfigResults.ScreenSaver = if ($screenSuccess -eq $screenTotal) { "SUCCESS" } elseif ($screenSuccess -gt 0) { "PARTIAL" } else { "FAILED" }

# ============================================
# 9. OPTIMIZE VIRTUAL MEMORY
# ============================================
Write-Host "`n[9/13] Optimizing Virtual Memory..." -ForegroundColor Yellow

try {
    # Let Windows manage page file automatically
    $computerSystem = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges -ErrorAction Stop
    $computerSystem.AutomaticManagedPagefile = $true
    $computerSystem.Put() | Out-Null
    Write-Status "Virtual memory set to system managed (optimal for VMs)" "SUCCESS"
    $script:ConfigResults.VirtualMemory = "SUCCESS"
} catch {
    Write-Status "Failed to configure virtual memory: $_" "WARNING"
    $script:ConfigResults.VirtualMemory = "FAILED"
}

# ============================================
# 10. CONFIGURE WINDOWS DEFENDER EXCLUSIONS FOR VM FOLDERS
# ============================================
Write-Host "`n[10/13] Configuring Windows Defender..." -ForegroundColor Yellow

$defenderSuccess = 0
try {
    # Common VM directories to exclude
    $vmPaths = @(
        "$env:PUBLIC\Documents\Hyper-V",
        "C:\Users\Public\Documents\Hyper-V",
        "C:\ProgramData\Microsoft\Windows\Hyper-V",
        "C:\VMs"
    )

    foreach ($path in $vmPaths) {
        if (Test-Path $path) {
            try {
                Add-MpPreference -ExclusionPath $path -ErrorAction Stop
                Write-Status "Added Defender exclusion for: $path" "SUCCESS"
                $defenderSuccess++
            } catch {
                Write-Status "Could not add exclusion for: $path" "WARNING"
            }
        }
    }

    # Exclude common VM file extensions
    try {
        $vmExtensions = @("vhd", "vhdx", "avhd", "avhdx", "vmcx", "vmrs", "iso")
        foreach ($ext in $vmExtensions) {
            Add-MpPreference -ExclusionExtension $ext -ErrorAction SilentlyContinue
        }
        Write-Status "VM file extensions excluded from scanning" "SUCCESS"
        $defenderSuccess++
    } catch {
        Write-Status "Could not add file extension exclusions" "WARNING"
    }

    $script:ConfigResults.Defender = if ($defenderSuccess -gt 0) { "SUCCESS" } else { "SKIPPED" }
} catch {
    Write-Status "Windows Defender configuration unavailable: $_" "WARNING"
    $script:ConfigResults.Defender = "SKIPPED"
}

# ============================================
# 11. DISABLE SYSTEM SOUNDS AND NOTIFICATIONS
# ============================================
Write-Host "`n[11/13] Disabling System Sounds..." -ForegroundColor Yellow

if (Set-RegistryValue -Path "HKCU:\AppEvents\Schemes" -Name "(Default)" -Value ".None" -Type "String") {
    Write-Status "System sounds disabled" "SUCCESS"
    $script:ConfigResults.SystemSounds = "SUCCESS"
} else {
    Write-Status "Failed to disable system sounds" "WARNING"
    $script:ConfigResults.SystemSounds = "FAILED"
}

# ============================================
# 12. ENABLE AND VERIFY HYPER-V
# ============================================
Write-Host "`n[12/13] Enabling Hyper-V and Virtualization..." -ForegroundColor Yellow

$virtSuccess = 0
$hypervNeedsReboot = $false

try {
    $hypervFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -ErrorAction SilentlyContinue

    if ($hypervFeature -and $hypervFeature.State -eq "Enabled") {
        Write-Status "Hyper-V is already enabled" "SUCCESS"
        $virtSuccess++
    } elseif ($hypervFeature -and $hypervFeature.State -eq "Disabled") {
        Write-Status "Hyper-V is available but disabled. Enabling now..." "INFO"

        if (-not $WhatIf) {
            try {
                $result = Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart -ErrorAction Stop
                if ($result.RestartNeeded) {
                    $hypervNeedsReboot = $true
                    Write-Status "Hyper-V enabled successfully (restart required)" "SUCCESS"
                } else {
                    Write-Status "Hyper-V enabled successfully" "SUCCESS"
                }
                $virtSuccess++
            } catch {
                Write-Status "Failed to enable Hyper-V: $_" "ERROR"
                Write-Host "  You may need to enable virtualization in BIOS first" -ForegroundColor Gray
            }
        } else {
            Write-Host "  [WhatIf] Would enable Hyper-V feature" -ForegroundColor Magenta
            $virtSuccess++
        }
    } else {
        Write-Status "Hyper-V feature not available on this Windows edition" "WARNING"
        Write-Host "  Hyper-V requires Windows 10/11 Pro, Enterprise, or Education" -ForegroundColor Gray
    }
} catch {
    Write-Status "Could not check Hyper-V status: $_" "WARNING"
}

try {
    # Check if virtualization is enabled in BIOS
    $vmPlatform = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent
    if ($vmPlatform) {
        Write-Status "Hardware virtualization is enabled" "SUCCESS"
        $virtSuccess++
    } else {
        Write-Status "Hardware virtualization may not be enabled in BIOS" "WARNING"
        Write-Host "  Enable VT-x/AMD-V in BIOS settings to use Hyper-V" -ForegroundColor Gray
    }
} catch {
    Write-Status "Could not verify hardware virtualization: $_" "WARNING"
}

$script:ConfigResults.Virtualization = if ($virtSuccess -ge 2) { "SUCCESS" } elseif ($virtSuccess -eq 1) { "PARTIAL" } else { "WARNING" }

# ============================================
# 13. ADDITIONAL OPTIMIZATIONS
# ============================================
Write-Host "`n[13/13] Applying Additional Optimizations..." -ForegroundColor Yellow

$additionalSuccess = 0
$additionalTotal = 15

# Disable Windows Search indexing for better disk performance
try {
    $service = Get-Service -Name "WSearch" -ErrorAction SilentlyContinue
    if ($service -and -not $WhatIf) {
        Stop-Service -Name "WSearch" -Force -ErrorAction Stop
        Set-Service -Name "WSearch" -StartupType Disabled -ErrorAction Stop
        Write-Status "Windows Search indexing disabled" "SUCCESS"
        $additionalSuccess++
    } elseif ($WhatIf) {
        Write-Host "  [WhatIf] Would disable Windows Search service" -ForegroundColor Magenta
        $additionalSuccess++
    }
} catch {
    Write-Status "Could not disable Windows Search: $_" "WARNING"
}

# Disable Windows Error Reporting
if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1) {
    Write-Status "Windows Error Reporting disabled" "SUCCESS"
    $additionalSuccess++
}

# Disable automatic maintenance
if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Value 1) {
    Write-Status "Automatic maintenance disabled" "SUCCESS"
    $additionalSuccess++
}

# Optimize network for file sharing (disable Large Send Offload for compatibility)
try {
    if (-not $WhatIf) {
        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq "Up"
        foreach ($adapter in $adapters) {
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Large Send Offload V2 (IPv4)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Large Send Offload V2 (IPv6)" -DisplayValue "Disabled" -ErrorAction SilentlyContinue
        }
        Write-Status "Network adapters optimized for VM host" "SUCCESS"
        $additionalSuccess++
    } else {
        Write-Host "  [WhatIf] Would optimize network adapter settings" -ForegroundColor Magenta
        $additionalSuccess++
    }
} catch {
    Write-Status "Could not optimize network adapters: $_" "WARNING"
}

# Enable Remote Desktop (useful for VM host management)
if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0) {
    Write-Status "Remote Desktop enabled" "SUCCESS"
    $additionalSuccess++

    # Enable RDP through firewall
    try {
        if (-not $WhatIf) {
            netsh advfirewall firewall set rule group="remote desktop" new enable=Yes 2>&1 | Out-Null
            Write-Status "RDP firewall rules enabled" "SUCCESS"
        }
    } catch {
        Write-Status "Could not enable RDP firewall rules: $_" "WARNING"
    }
}

# Disable Superfetch/SysMain (can interfere with VM disk I/O)
try {
    $service = Get-Service -Name "SysMain" -ErrorAction SilentlyContinue
    if ($service -and -not $WhatIf) {
        Stop-Service -Name "SysMain" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "SysMain" -StartupType Disabled -ErrorAction Stop
        Write-Status "Superfetch/SysMain disabled (better for VM hosts)" "SUCCESS"
        $additionalSuccess++
    } elseif ($WhatIf) {
        Write-Host "  [WhatIf] Would disable SysMain service" -ForegroundColor Magenta
        $additionalSuccess++
    }
} catch {
    Write-Status "Could not disable SysMain: $_" "WARNING"
}

# Disable memory compression (can conflict with VMs)
try {
    if (-not $WhatIf) {
        Disable-MMAgent -MemoryCompression -ErrorAction Stop
        Write-Status "Memory compression disabled (better for VM hosts)" "SUCCESS"
        $additionalSuccess++
    } else {
        Write-Host "  [WhatIf] Would disable memory compression" -ForegroundColor Magenta
        $additionalSuccess++
    }
} catch {
    Write-Status "Could not disable memory compression: $_" "WARNING"
}

# Disable visual effects for better performance
if (Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2) {
    Write-Status "Visual effects set to best performance" "SUCCESS"
    $additionalSuccess++
}

# Optimize processor scheduling for background services (better for VM host)
if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 24) {
    Write-Status "Processor scheduling optimized for background services" "SUCCESS"
    $additionalSuccess++
}

# Disable Storage Sense
if (Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Value 0) {
    Write-Status "Storage Sense disabled" "SUCCESS"
    $additionalSuccess++
}

# Disable Windows Telemetry
if (Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0) {
    Write-Status "Windows Telemetry disabled" "SUCCESS"
    $additionalSuccess++
}

# Disable scheduled defragmentation
try {
    if (-not $WhatIf) {
        Disable-ScheduledTask -TaskName "ScheduledDefrag" -TaskPath "\Microsoft\Windows\Defrag\" -ErrorAction SilentlyContinue
        Write-Status "Scheduled defragmentation disabled" "SUCCESS"
        $additionalSuccess++
    } else {
        Write-Host "  [WhatIf] Would disable scheduled defragmentation" -ForegroundColor Magenta
        $additionalSuccess++
    }
} catch {
    Write-Status "Could not disable scheduled defragmentation: $_" "WARNING"
}

# Prevent network adapters from sleeping
try {
    if (-not $WhatIf) {
        $adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq "Up"
        foreach ($adapter in $adapters) {
            $powerMgmt = Get-CimInstance -ClassName MSPower_DeviceEnable -Namespace root\wmi -ErrorAction SilentlyContinue | Where-Object InstanceName -Like "*$($adapter.InterfaceGuid)*"
            if ($powerMgmt) {
                $powerMgmt | Set-CimInstance -Property @{Enable = $false} -ErrorAction SilentlyContinue
            }
        }
        Write-Status "Network adapter power management disabled" "SUCCESS"
        $additionalSuccess++
    } else {
        Write-Host "  [WhatIf] Would disable network adapter power management" -ForegroundColor Magenta
        $additionalSuccess++
    }
} catch {
    Write-Status "Could not configure network power management: $_" "WARNING"
}

# Disable crash dumps or set to minimal (kernel only)
if (Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "CrashDumpEnabled" -Value 2) {
    Write-Status "Crash dumps set to kernel memory dump only" "SUCCESS"
    $additionalSuccess++
}

# Disable CPU core parking (all cores always available)
try {
    powercfg /setacvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 100 2>&1 | Out-Null
    powercfg /setdcvalueindex SCHEME_CURRENT 54533251-82be-4824-96c1-47b60b740d00 0cc5b647-c1df-4637-891a-dec35c318583 100 2>&1 | Out-Null
    Write-Status "CPU core parking disabled (all cores available)" "SUCCESS"
    $additionalSuccess++
} catch {
    Write-Status "Could not disable CPU core parking: $_" "WARNING"
}

$script:ConfigResults.Additional = if ($additionalSuccess -ge $additionalTotal) { "SUCCESS" } elseif ($additionalSuccess -gt 0) { "PARTIAL" } else { "FAILED" }

# ============================================
# SUMMARY
# ============================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Configuration Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Count successes and failures
$successCount = 0
$partialCount = 0
$failedCount = 0
$skippedCount = 0

function Get-StatusSymbol {
    param([string]$Status)
    switch ($Status) {
        "SUCCESS" { return "[+]", "Green" }
        "PARTIAL" { return "[~]", "Yellow" }
        "FAILED"  { return "[-]", "Red" }
        "SKIPPED" { return "[*]", "Gray" }
        "INFO"    { return "[i]", "Cyan" }
        default   { return "[?]", "Gray" }
    }
}

Write-Host "Configuration Results:" -ForegroundColor White
Write-Host ""

foreach ($key in $script:ConfigResults.Keys | Sort-Object) {
    $status = $script:ConfigResults[$key]
    $symbol, $color = Get-StatusSymbol -Status $status

    # Format the key name
    $displayName = switch ($key) {
        "AutoLogin"         { "Auto-Login" }
        "SleepHibernation"  { "Sleep & Hibernation" }
        "PowerPlan"         { "Power Plan (High Performance)" }
        "FastStartup"       { "Fast Startup Disabled" }
        "NetworkPrivate"    { "Network Set to Private" }
        "FileSharing"       { "File Sharing & Discovery" }
        "WindowsUpdate"     { "Windows Update Auto-Restart" }
        "ScreenSaver"       { "Screen Saver & Lock Screen" }
        "VirtualMemory"     { "Virtual Memory" }
        "Defender"          { "Windows Defender Exclusions" }
        "SystemSounds"      { "System Sounds" }
        "Virtualization"    { "Hyper-V & Virtualization" }
        "Additional"        { "Additional Optimizations" }
        default             { $key }
    }

    Write-Host "  $symbol " -ForegroundColor $color -NoNewline
    Write-Host "$displayName`: " -NoNewline
    Write-Host $status -ForegroundColor $color

    # Count results
    switch ($status) {
        "SUCCESS" { $successCount++ }
        "PARTIAL" { $partialCount++ }
        "FAILED"  { $failedCount++ }
        "SKIPPED" { $skippedCount++ }
        "INFO"    { $skippedCount++ }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Summary: " -NoNewline
Write-Host "$successCount successful" -ForegroundColor Green -NoNewline
if ($partialCount -gt 0) {
    Write-Host ", $partialCount partial" -ForegroundColor Yellow -NoNewline
}
if ($failedCount -gt 0) {
    Write-Host ", $failedCount failed" -ForegroundColor Red -NoNewline
}
if ($skippedCount -gt 0) {
    Write-Host ", $skippedCount skipped/info" -ForegroundColor Gray -NoNewline
}
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($failedCount -gt 0) {
    Write-Host "NOTICE: Some configurations failed. The script continued and applied what it could." -ForegroundColor Yellow
    Write-Host "Review the output above for details on what failed." -ForegroundColor Yellow
    Write-Host ""
}

if (-not $WhatIf) {
    Write-Host "IMPORTANT: A restart is required for all changes to take effect." -ForegroundColor Yellow

    if ($hypervNeedsReboot) {
        Write-Host "NOTICE: Hyper-V was enabled and requires a restart to complete installation." -ForegroundColor Yellow
    }
} else {
    Write-Host "WhatIf mode complete - no changes were made to the system." -ForegroundColor Magenta
}

Write-Host ""

if (-not $NoRestart -and -not $WhatIf) {
    $restart = Read-Host "Would you like to restart now? (Y/N)"
    if ($restart -eq 'Y' -or $restart -eq 'y') {
        Write-Host "Restarting in 10 seconds... Press Ctrl+C to cancel" -ForegroundColor Yellow
        Start-Sleep -Seconds 10

        # Stop transcript before restart
        if ($LogFile) {
            try { Stop-Transcript | Out-Null } catch { }
        }

        Restart-Computer -Force
    } else {
        Write-Host "Please restart your computer manually to apply all changes." -ForegroundColor Yellow
    }
} elseif ($NoRestart) {
    Write-Host "Restart skipped (-NoRestart parameter specified)." -ForegroundColor Gray
    Write-Host "Please restart your computer manually to apply all changes." -ForegroundColor Yellow
}

Write-Host ""

# Post-Configuration Recommendations
if (-not $WhatIf) {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Post-Configuration Recommendations" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "After restart, consider these additional steps:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. VM Storage:" -ForegroundColor White
    Write-Host "   - Store VMs on dedicated disk (not C:) for better performance" -ForegroundColor Gray
    Write-Host "   - Consider RAID configuration for VM storage" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. Networking:" -ForegroundColor White
    Write-Host "   - Create Hyper-V Virtual Switches via Hyper-V Manager" -ForegroundColor Gray
    Write-Host "   - Configure static IP for host if running production VMs" -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. Memory:" -ForegroundColor White
    Write-Host "   - Reserve at least 4GB RAM for host OS" -ForegroundColor Gray
    Write-Host "   - Consider enabling Dynamic Memory for VMs" -ForegroundColor Gray
    Write-Host ""
    Write-Host "4. Security:" -ForegroundColor White
    Write-Host "   - Configure Windows Firewall rules for VM traffic" -ForegroundColor Gray
    Write-Host "   - Review auto-login security implications" -ForegroundColor Gray
    Write-Host "   - Consider BitLocker for VM storage drives" -ForegroundColor Gray
    Write-Host ""
    Write-Host "5. Backup:" -ForegroundColor White
    Write-Host "   - Set up automated VM backups" -ForegroundColor Gray
    Write-Host "   - Export VM configurations regularly" -ForegroundColor Gray
    Write-Host ""
    Write-Host "6. Monitoring:" -ForegroundColor White
    Write-Host "   - Enable Hyper-V performance counters" -ForegroundColor Gray
    Write-Host "   - Monitor host resource usage (CPU, RAM, Disk I/O)" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "Configuration script completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

# Stop transcript if running
if ($LogFile) {
    try {
        Stop-Transcript
        Write-Host "Log saved to: $LogFile" -ForegroundColor Gray
    } catch { }
}
