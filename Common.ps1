#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Shared functions for Hyper-V VM management scripts.

.DESCRIPTION
    Common functionality used by Deploy-VM.ps1, Reset-VM.ps1, Set-Network.ps1, and other scripts.
    Including: logging, state management, VM operations, and network configuration.

.NOTES
    This module should be dot-sourced by other scripts in the same directory.
#>

#region Script-Level Variables
$script:LogFilePath = $null
$script:StateLockMutex = $null

# Common constants
$script:InternalSwitch = "Internal"
$script:ExternalSwitch = "External"
$script:HostIP = "10.0.0.1"
$script:StartIP = 10

# Registry path for VM state storage
$script:RegistryBasePath = "HKLM:\SOFTWARE\HyperV-VMM"
$script:RegistryInstancesPath = "HKLM:\SOFTWARE\HyperV-VMM\Instances"

# TP-Link OUI prefixes for MAC addresses
$script:TpLinkPrefixes = @('00-27-19','00-1F-3F','00-1D-0F','00-22-B0','00-23-CD','00-25-86','00-25-C5','00-27-A4','10-FE-ED','14-CF-92','18-0F-76','1C-3B-F3','20-76-00','20-E2-8A','24-A4-3C','28-2C-B2','30-B5-C2','30-FC-68','34-EA-E7','3C-84-6A','40-16-7E','44-00-4D','44-D6-E3','48-5B-39','4C-ED-FB','50-3E-AA','50-C7-BF','54-AF-97','5C-E9-31','60-32-B1','60-E3-27','64-66-B3','68-1C-A2','6C-5A-B0','70-4F-57','74-DA-88','78-44-76','7C-8B-CA','80-EA-07','84-16-F9','88-1D-FC','8C-15-C7','8C-FE-57','90-6F-18','90-F6-52','94-0C-6D','98-25-4A','98-DE-D0','9C-A2-F4','A0-63-91','A0-F3-C1','A4-2B-B0','A8-5E-45','AC-15-A2','AC-84-C6','B0-4E-26','B0-95-75','B4-B0-24','B8-27-EB','BC-46-99','C0-25-E9','C4-6E-1F','C8-0E-14','C8-3A-35','C8-D7-19','CC-32-E5','D0-76-8F','D4-6E-0E','D8-0D-17','DC-15-C8','E0-28-6D','E4-9A-79','E8-48-B8','E8-94-F6','EC-08-6B','F0-D1-A9','F4-28-53','F4-6D-04','F4-EC-38','F4-F2-6D','F8-1A-67','FC-EC-DA')
#endregion

#region Logging Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info','Success','Warning','Error','Debug')][string]$Level = 'Info'
    )

    $colors = @{
        Info = 'Cyan'
        Success = 'Green'
        Warning = 'Yellow'
        Error = 'Red'
        Debug = 'DarkGray'
    }

    $prefixes = @{
        Info = '[INFO]'
        Success = '[OK]'
        Warning = '[WARN]'
        Error = '[ERROR]'
        Debug = '[DEBUG]'
    }

    # Console output
    Write-Host "$($prefixes[$Level]) $Message" -ForegroundColor $colors[$Level]

    # File output (if log file is configured)
    if ($script:LogFilePath) {
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $logEntry = "[$timestamp] $($prefixes[$Level]) $Message"
        try {
            Add-Content -Path $script:LogFilePath -Value $logEntry -ErrorAction SilentlyContinue
        }
        catch {
            # Silently fail if log file write fails
        }
    }
}

function Initialize-LogFile {
    param(
        [string]$LogFile,
        [string]$DefaultFolder
    )

    if ([string]::IsNullOrWhiteSpace($LogFile)) {
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $LogFile = Join-Path $DefaultFolder "vm-operation-$timestamp.log"
    }

    # Create log file directory if it doesn't exist
    $logDir = Split-Path $LogFile -Parent
    if ($logDir -and -not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    $script:LogFilePath = $LogFile
    return $LogFile
}

#endregion

#region Registry-Based State Management Functions
# Registry structure: HKLM:\SOFTWARE\HyperV-VMM\Instances\{VM-GUID}
# VMs are indexed by their immutable GUID, with Name stored as a property

function Initialize-RegistryState {
    <#
    .SYNOPSIS
        Initializes the registry structure for VM state storage
    #>
    try {
        if (-not (Test-Path $script:RegistryBasePath)) {
            New-Item -Path $script:RegistryBasePath -Force | Out-Null
            Write-Log "Created registry base path: $script:RegistryBasePath" -Level Success
        }
        if (-not (Test-Path $script:RegistryInstancesPath)) {
            New-Item -Path $script:RegistryInstancesPath -Force | Out-Null
            Write-Log "Created registry instances path: $script:RegistryInstancesPath" -Level Success
        }

        # Initialize global settings if not present
        $settings = Get-ItemProperty -Path $script:RegistryBasePath -ErrorAction SilentlyContinue
        if (-not $settings.Version) {
            Set-ItemProperty -Path $script:RegistryBasePath -Name "Version" -Value "2.0"
            Set-ItemProperty -Path $script:RegistryBasePath -Name "Created" -Value (Get-Date).ToString("o")
        }
        Set-ItemProperty -Path $script:RegistryBasePath -Name "Updated" -Value (Get-Date).ToString("o")

        return $true
    }
    catch {
        Write-Log "Failed to initialize registry state: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Get-VMInstanceByID {
    <#
    .SYNOPSIS
        Gets VM instance data by VM GUID - combines registry (IP/Configured) with Hyper-V state
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMID
    )

    # Get VM from Hyper-V
    $vm = Get-VM | Where-Object { $_.VMId.Guid -eq $VMID }
    if (-not $vm) {
        return $null
    }

    # Get registry data (only IP and Configured status)
    $instancePath = Join-Path $script:RegistryInstancesPath $VMID
    $internalIP = ""
    $configured = $false

    if (Test-Path $instancePath) {
        try {
            $props = Get-ItemProperty -Path $instancePath -ErrorAction Stop
            $internalIP = $props.InternalIP
            $configured = [bool]$props.Configured
        }
        catch { }
    }

    # Get VHD path
    $vhdPath = (Get-VMHardDiskDrive -VMName $vm.Name -ErrorAction SilentlyContinue | Select-Object -First 1).Path

    # Get GPU info
    $gpuAdapter = Get-VMGpuPartitionAdapter -VMName $vm.Name -ErrorAction SilentlyContinue
    $assignedGPU = ""
    $gpuName = ""
    if ($gpuAdapter) {
        $assignedGPU = $gpuAdapter.InstancePath
        $gpuName = (Get-AllAvailableGPUs | Where-Object { $_.InstancePath -eq $assignedGPU }).FriendlyName
    }

    return @{
        ID = $VMID
        Name = $vm.Name
        VHDPath = $vhdPath
        InternalIP = $internalIP
        AssignedGPU = $assignedGPU
        GPUName = $gpuName
        Memory = $vm.MemoryStartup
        CPU = $vm.ProcessorCount
        Configured = $configured
    }
}

function Get-VMInstanceFromRegistry {
    <#
    .SYNOPSIS
        Gets VM instance data by VM name - combines registry (IP/Configured) with Hyper-V state
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMName
    )

    # Get VM from Hyper-V
    $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if (-not $vm) {
        return $null
    }

    $vmID = $vm.VMId.Guid

    # Get registry data (only IP and Configured status)
    $instancePath = Join-Path $script:RegistryInstancesPath $vmID
    $internalIP = ""
    $configured = $false

    # If registry entry doesn't exist, VM is not managed
    if (-not (Test-Path $instancePath)) {
        return $null
    }

    try {
        $props = Get-ItemProperty -Path $instancePath -ErrorAction Stop
        $internalIP = $props.InternalIP
        $configured = [bool]$props.Configured
    }
    catch { }

    # Get VHD path
    $vhdPath = (Get-VMHardDiskDrive -VMName $VMName -ErrorAction SilentlyContinue | Select-Object -First 1).Path

    # Get GPU info
    $gpuAdapter = Get-VMGpuPartitionAdapter -VMName $VMName -ErrorAction SilentlyContinue
    $assignedGPU = ""
    $gpuName = ""
    if ($gpuAdapter) {
        $assignedGPU = $gpuAdapter.InstancePath
        $gpuName = (Get-AllAvailableGPUs | Where-Object { $_.InstancePath -eq $assignedGPU }).FriendlyName
    }

    return @{
        ID = $vmID
        Name = $VMName
        VHDPath = $vhdPath
        InternalIP = $internalIP
        AssignedGPU = $assignedGPU
        GPUName = $gpuName
        Memory = $vm.MemoryStartup
        CPU = $vm.ProcessorCount
        Configured = $configured
    }
}

function Save-VMInstanceToRegistry {
    <#
    .SYNOPSIS
        Saves VM instance data to registry (indexed by VM GUID)
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMID,
        [Parameter(Mandatory=$true)]
        [hashtable]$VMData
    )

    try {
        Initialize-RegistryState | Out-Null

        $instancePath = Join-Path $script:RegistryInstancesPath $VMID

        if (-not (Test-Path $instancePath)) {
            New-Item -Path $instancePath -Force | Out-Null
        }

        # Save all properties
        foreach ($key in $VMData.Keys) {
            if ($null -ne $VMData[$key]) {
                Set-ItemProperty -Path $instancePath -Name $key -Value $VMData[$key]
            }
        }

        # Update timestamp
        Set-ItemProperty -Path $instancePath -Name "Updated" -Value (Get-Date).ToString("o")
        Set-ItemProperty -Path $script:RegistryBasePath -Name "Updated" -Value (Get-Date).ToString("o")

        $vmName = if ($VMData.Name) { $VMData.Name } else { $VMID }
        Write-Log "VM instance saved to registry: $vmName ($VMID)" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to save VM instance to registry: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Remove-VMInstanceFromRegistry {
    <#
    .SYNOPSIS
        Removes VM instance data from registry by GUID or Name
    #>
    param(
        [string]$VMID = "",
        [string]$VMName = ""
    )

    $instancePath = $null

    # Try by ID first
    if (-not [string]::IsNullOrWhiteSpace($VMID)) {
        $instancePath = Join-Path $script:RegistryInstancesPath $VMID
    }
    # Fall back to searching by name
    elseif (-not [string]::IsNullOrWhiteSpace($VMName)) {
        $vmData = Get-VMInstanceFromRegistry -VMName $VMName
        if ($vmData) {
            $instancePath = Join-Path $script:RegistryInstancesPath $vmData.ID
        }
    }

    if ($instancePath -and (Test-Path $instancePath)) {
        try {
            Remove-Item -Path $instancePath -Recurse -Force
            Write-Log "VM instance removed from registry" -Level Success
            return $true
        }
        catch {
            Write-Log "Failed to remove VM instance from registry: $($_.Exception.Message)" -Level Error
            return $false
        }
    }

    return $true
}

function Get-AllVMInstancesFromRegistry {
    <#
    .SYNOPSIS
        Gets all VM instances from registry
    #>

    if (-not (Test-Path $script:RegistryInstancesPath)) {
        return @()
    }

    try {
        $instances = @()
        $subKeys = Get-ChildItem -Path $script:RegistryInstancesPath -ErrorAction SilentlyContinue

        foreach ($key in $subKeys) {
            $vmID = $key.PSChildName
            $vmData = Get-VMInstanceByID -VMID $vmID
            if ($vmData) {
                $instances += $vmData
            }
        }

        return $instances
    }
    catch {
        Write-Log "Failed to enumerate VM instances from registry: $($_.Exception.Message)" -Level Error
        return @()
    }
}

function Get-GlobalSettingsFromRegistry {
    <#
    .SYNOPSIS
        Gets global settings from registry (template path, VHD folder, etc.)
    #>

    if (-not (Test-Path $script:RegistryBasePath)) {
        return $null
    }

    try {
        $props = Get-ItemProperty -Path $script:RegistryBasePath -ErrorAction Stop
        return @{
            Version = $props.Version
            Created = $props.Created
            Updated = $props.Updated
            SourceVHDX = $props.SourceVHDX
            TemplateVHDX = $props.TemplateVHDX
            VHDFolder = $props.VHDFolder
            DefaultMemory = $props.DefaultMemory
            DefaultCPU = $props.DefaultCPU
        }
    }
    catch {
        Write-Log "Failed to read global settings from registry: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Save-GlobalSettingsToRegistry {
    <#
    .SYNOPSIS
        Saves global settings to registry
    #>
    param(
        [hashtable]$Settings
    )

    try {
        Initialize-RegistryState | Out-Null

        foreach ($key in $Settings.Keys) {
            if ($null -ne $Settings[$key]) {
                Set-ItemProperty -Path $script:RegistryBasePath -Name $key -Value $Settings[$key]
            }
        }

        Set-ItemProperty -Path $script:RegistryBasePath -Name "Updated" -Value (Get-Date).ToString("o")

        Write-Log "Global settings saved to registry" -Level Success
        return $true
    }
    catch {
        Write-Log "Failed to save global settings to registry: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-VMExistsInRegistry {
    <#
    .SYNOPSIS
        Checks if a VM exists in the registry by name or ID
    #>
    param(
        [string]$VMName = "",
        [string]$VMID = ""
    )

    if (-not [string]::IsNullOrWhiteSpace($VMID)) {
        $instancePath = Join-Path $script:RegistryInstancesPath $VMID
        return (Test-Path $instancePath)
    }

    if (-not [string]::IsNullOrWhiteSpace($VMName)) {
        $vmData = Get-VMInstanceFromRegistry -VMName $VMName
        return ($null -ne $vmData)
    }

    return $false
}

function Sync-VMNameInRegistry {
    <#
    .SYNOPSIS
        Updates the VM name in registry if the VM was renamed in Hyper-V
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$VMID,
        [Parameter(Mandatory=$true)]
        [string]$NewName
    )

    $instancePath = Join-Path $script:RegistryInstancesPath $VMID

    if (Test-Path $instancePath) {
        try {
            Set-ItemProperty -Path $instancePath -Name "Name" -Value $NewName
            Set-ItemProperty -Path $instancePath -Name "Updated" -Value (Get-Date).ToString("o")
            Write-Log "VM name updated in registry: $NewName" -Level Success
            return $true
        }
        catch {
            Write-Log "Failed to update VM name in registry: $($_.Exception.Message)" -Level Error
            return $false
        }
    }

    return $false
}

#endregion

#region Credential Management Functions

function New-VMCredential {
    <#
    .SYNOPSIS
        Creates a PSCredential object from username and password strings
    #>
    param(
        [string]$Username,
        [string]$Password
    )

    if ([string]::IsNullOrWhiteSpace($Username)) {
        throw "Username cannot be empty"
    }
    if ([string]::IsNullOrWhiteSpace($Password)) {
        throw "Password cannot be empty"
    }

    $securePassword = ConvertTo-SecureString $Password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($Username, $securePassword)
}

#endregion

#region VM Management Functions

function Test-VMExists {
    param([string]$VMName)

    $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    return ($null -ne $vm)
}

function Get-VMCurrentState {
    param([string]$VMName)

    $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
    if ($vm) {
        return @{
            Exists = $true
            State = $vm.State
            Heartbeat = $vm.Heartbeat
        }
    }
    return @{
        Exists = $false
        State = "NotFound"
        Heartbeat = "N/A"
    }
}

function Start-VMSafely {
    param(
        [string]$VMName,
        [int]$WaitSeconds = 2,
        [switch]$WhatIf
    )

    if ($WhatIf) {
        Write-Log "[WhatIf] Would start VM: $VMName" -Level Info
        return $true
    }

    try {
        $vm = Get-VM -Name $VMName -ErrorAction Stop

        if ($vm.State -eq 'Running') {
            Write-Log "VM '$VMName' is already running" -Level Debug
            return $true
        }

        Write-Log "Starting VM: $VMName" -Level Info
        Start-VM -Name $VMName -ErrorAction Stop

        if ($WaitSeconds -gt 0) {
            Start-Sleep -Seconds $WaitSeconds
        }

        $vmState = (Get-VM -Name $VMName).State
        if ($vmState -eq 'Running') {
            Write-Log "VM started successfully" -Level Success
            return $true
        }
        else {
            Write-Log "VM failed to start (state: $vmState)" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Failed to start VM: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Stop-VMSafely {
    param(
        [string]$VMName,
        [int]$TimeoutSeconds = 30,
        [switch]$WaitForShutdown,
        [switch]$WhatIf
    )

    if ($WhatIf) {
        Write-Log "[WhatIf] Would stop VM: $VMName" -Level Info
        return $true
    }

    try {
        $vm = Get-VM -Name $VMName -ErrorAction Stop

        if ($vm.State -eq 'Off') {
            Write-Log "VM '$VMName' is already stopped" -Level Debug
            return $true
        }

        Write-Log "Stopping VM: $VMName" -Level Info
        Stop-VM -Name $VMName -Force -TurnOff -ErrorAction Stop

        if ($WaitForShutdown) {
            # Wait for VM to fully shut down
            $elapsed = 0
            while ($elapsed -lt $TimeoutSeconds) {
                $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
                if ($vm.State -eq 'Off') {
                    Write-Log "VM stopped successfully" -Level Success
                    return $true
                }
                Start-Sleep -Seconds 1
                $elapsed++
            }
            Write-Log "VM stop timeout exceeded ($TimeoutSeconds seconds)" -Level Warning
            return $false
        }
        else {
            Start-Sleep -Seconds 2
            return $true
        }
    }
    catch {
        Write-Log "Failed to stop VM: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Wait-VMHeartbeat {
    param(
        [string]$VMName,
        [int]$TimeoutSeconds = 90,
        [switch]$WhatIf
    )

    if ($WhatIf) {
        Write-Log "[WhatIf] Would wait for VM heartbeat: $VMName" -Level Info
        return $true
    }

    Write-Log "Waiting for VM heartbeat (timeout: $TimeoutSeconds seconds)..." -Level Info

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue

        if ($vm.State -eq 'Running' -and $vm.Heartbeat -match 'Ok') {
            Write-Log "VM heartbeat detected, waiting 5 more seconds for stability..." -Level Debug
            Start-Sleep -Seconds 5
            Write-Log "VM ready for configuration" -Level Success
            return $true
        }

        # Show progress every 10 seconds
        if ($elapsed % 10 -eq 0 -and $elapsed -gt 0) {
            Write-Log "  Still waiting... ($elapsed/$TimeoutSeconds seconds) - State: $($vm.State), Heartbeat: $($vm.Heartbeat)" -Level Debug
        }

        Start-Sleep -Seconds 2
        $elapsed += 2
    }

    Write-Log "VM heartbeat timeout ($TimeoutSeconds seconds)" -Level Error
    return $false
}

function Remove-VMCompletely {
    param(
        [string]$VMName,
        [string]$VHDPath,
        [switch]$IncludeVHD
    )

    try {
        # Stop VM if running
        Stop-VMSafely -VMName $VMName -ErrorAction SilentlyContinue | Out-Null

        # Get VHD path if not provided
        if (-not $VHDPath) {
            $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
            if ($vm) {
                $VHDPath = ($vm.HardDrives | Select-Object -First 1).Path
            }
        }

        # Remove VM
        $vm = Get-VM -Name $VMName -ErrorAction SilentlyContinue
        if ($vm) {
            Write-Log "Removing VM: $VMName"
            Remove-VM -Name $VMName -Force -ErrorAction Stop
        }

        # Remove VHD if requested
        if ($IncludeVHD -and $VHDPath -and (Test-Path $VHDPath)) {
            Write-Log "Removing VHD: $VHDPath"
            Remove-Item -Path $VHDPath -Force -ErrorAction Stop
        }

        return $true
    }
    catch {
        Write-Log "Failed to remove VM '$VMName': $($_.Exception.Message)" -Level Error
        return $false
    }
}

#endregion

#region Network Configuration Functions

function Configure-VMNetwork {
    <#
    .SYNOPSIS
        Configures network settings inside a VM using PowerShell Direct

    .DESCRIPTION
        Sets IP address, hostname, network profile to Private, and ProxiFyre firewall rules
        Uses MAC address matching to identify the correct network adapter
    #>
    param(
        [string]$VMName,
        [string]$InternalIP,
        [string]$Hostname,
        [PSCredential]$Credential,
        [string]$InternalMAC,
        [int]$MaxRetries = 3,
        [switch]$WhatIf
    )

    if ($WhatIf) {
        Write-Log "[WhatIf] Would configure network:" -Level Info
        Write-Log "[WhatIf]   VM: $VMName" -Level Info
        Write-Log "[WhatIf]   IP: $InternalIP" -Level Info
        Write-Log "[WhatIf]   Hostname: $Hostname" -Level Info
        Write-Log "[WhatIf]   Internal MAC: $InternalMAC" -Level Info
        Write-Log "[WhatIf]   Set all networks to Private" -Level Info
        Write-Log "[WhatIf]   Add ProxiFyre firewall rules (C:\ProxiFyre\ProxiFyre.exe)" -Level Info
        return $true
    }

    # Validate MAC address was provided
    if ([string]::IsNullOrWhiteSpace($InternalMAC)) {
        Write-Log "Internal MAC address not provided" -Level Error
        return $false
    }

    $internalMac = $InternalMAC
    Write-Log "Using Internal adapter MAC: $internalMac" -Level Info

    # Retry logic with exponential backoff
    $attempt = 0
    $success = $false

    while ($attempt -lt $MaxRetries -and -not $success) {
        $attempt++

        if ($attempt -gt 1) {
            $waitTime = [Math]::Pow(2, $attempt - 1)
            Write-Log "Retry attempt $attempt of $MaxRetries (waiting $waitTime seconds)..." -Level Warning
            Start-Sleep -Seconds $waitTime
        }
        else {
            Write-Log "Configuring network (attempt $attempt of $MaxRetries)..." -Level Info
        }

        try {
            # Execute network configuration inside the VM using PowerShell Direct
            $result = Invoke-Command -VMName $VMName -Credential $Credential -ErrorAction Stop -ScriptBlock {
                param($IP, $Hostname, $TargetMac)

                # Match adapter by MAC address
                $targetMacClean = $TargetMac -replace '[-:]', ''
                $adapters = @(Get-NetAdapter | Where-Object {
                    $_.Status -eq "Up" -and
                    $_.InterfaceDescription -like "*Hyper-V*" -and
                    ($_.MacAddress -replace '[-:]', '') -eq $targetMacClean
                })

                if ($adapters.Count -eq 0) {
                    return "ERROR: No Hyper-V adapter found with MAC $TargetMac"
                }

                if ($adapters.Count -gt 1) {
                    return "ERROR: Multiple adapters found with MAC $TargetMac - this indicates a MAC collision that should not happen"
                }

                $adapter = $adapters[0]

                # Remove existing IP addresses in the 10.0.0.0/24 range
                Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.IPAddress -like "10.0.0.*" } |
                    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

                # Set new IP address
                try {
                    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $IP -PrefixLength 24 -ErrorAction Stop | Out-Null
                    Start-Sleep -Seconds 2
                }
                catch {
                    return "ERROR: Failed to set IP address: $_"
                }

                # Set ALL networks to Private
                try {
                    Get-NetConnectionProfile -ErrorAction SilentlyContinue |
                        Set-NetConnectionProfile -NetworkCategory Private -ErrorAction SilentlyContinue
                }
                catch {
                    # Non-critical, continue
                }

                # Configure firewall rule for ProxiFyre
                try {
                    $proxiFyreExe = "C:\ProxiFyre\ProxiFyre.exe"
                    if (Test-Path $proxiFyreExe) {
                        # Remove existing rules for ProxiFyre
                        Get-NetFirewallRule -DisplayName "ProxiFyre" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

                        # Add new firewall rules (Inbound and Outbound)
                        New-NetFirewallRule -DisplayName "ProxiFyre" -Direction Inbound -Program $proxiFyreExe -Action Allow -Profile Any -ErrorAction Stop | Out-Null
                        New-NetFirewallRule -DisplayName "ProxiFyre" -Direction Outbound -Program $proxiFyreExe -Action Allow -Profile Any -ErrorAction Stop | Out-Null
                    }
                }
                catch {
                    # Non-critical, continue
                }

                # Rename computer
                try {
                    $currentName = $env:COMPUTERNAME
                    if ($currentName -ne $Hostname) {
                        Rename-Computer -NewName $Hostname -Force -ErrorAction Stop | Out-Null
                        return "SUCCESS: IP=$IP, Hostname=$Hostname (renamed from $currentName)"
                    }
                    else {
                        return "SUCCESS: IP=$IP, Hostname=$Hostname (already set)"
                    }
                }
                catch {
                    return "PARTIAL: IP=$IP set, hostname rename failed: $_"
                }
            } -ArgumentList $InternalIP, $Hostname, $internalMac

            # Check result
            if ($result -like "SUCCESS:*" -or $result -like "PARTIAL:*") {
                Write-Log "Configuration result: $result" -Level Success
                $success = $true
            }
            else {
                throw "Configuration returned: $result"
            }
        }
        catch {
            if ($attempt -eq $MaxRetries) {
                Write-Log "Network configuration failed after $MaxRetries attempts: $($_.Exception.Message)" -Level Error
                return $false
            }
            else {
                Write-Log "Attempt $attempt failed: $($_.Exception.Message)" -Level Warning
            }
        }
    }

    return $success
}

#endregion

#region Utility Functions

function Test-AdministratorPrivileges {
    <#
    .SYNOPSIS
        Checks if script is running with administrator privileges
    #>
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator"
    }
    Write-Log "Administrator privileges: OK" -Level Success
}

function Get-RandomMac {
    <#
    .SYNOPSIS
        Generates a random MAC address using TP-Link OUI prefixes
    #>
    $prefix = ($script:TpLinkPrefixes | Get-Random) -replace '-', ''
    $mac = $prefix
    for ($i = 0; $i -lt 3; $i++) {
        $mac += '{0:X2}' -f (Get-Random -Maximum 256)
    }
    return $mac
}

function Set-VMStaticMac {
    <#
    .SYNOPSIS
        Assigns a unique random TP-Link MAC to a VM network adapter.
        Replaces dynamic Hyper-V MACs or generates new ones.
    .PARAMETER VMName
        Name of the VM
    .PARAMETER SwitchName
        Name of the virtual switch the adapter is connected to (used to identify the adapter)
    .PARAMETER Force
        Force replacement even if current MAC is already static
    .RETURNS
        The assigned MAC address
    #>
    param(
        [Parameter(Mandatory=$true)][string]$VMName,
        [Parameter(Mandatory=$true)][string]$SwitchName,
        [switch]$Force
    )

    # Get adapter by switch name (more reliable than adapter name which can be duplicated)
    $adapter = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue |
               Where-Object { $_.SwitchName -eq $SwitchName } |
               Select-Object -First 1
    if (-not $adapter) {
        throw "No adapter connected to switch '$SwitchName' found on VM '$VMName'"
    }

    $isDynamic = $adapter.DynamicMacAddressEnabled
    $currentMac = $adapter.MacAddress

    # Skip if already static and not forced
    if (-not $Force -and -not $isDynamic) {
        return $currentMac
    }

    # Generate unique MAC with collision detection
    $macAssigned = $false
    $maxAttempts = 100
    $attempts = 0
    $newMac = ""

    while (-not $macAssigned -and $attempts -lt $maxAttempts) {
        $allMacs = @(Get-VM | Get-VMNetworkAdapter | ForEach-Object { $_.MacAddress })
        $newMac = Get-RandomMac

        if ($newMac -notin $allMacs) {
            try {
                # Use the adapter object directly via pipeline to avoid name ambiguity
                $adapter | Set-VMNetworkAdapter -StaticMacAddress $newMac -MacAddressSpoofing On -ErrorAction Stop

                # Verify assignment by re-fetching the specific adapter
                $updatedAdapter = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue |
                                  Where-Object { $_.SwitchName -eq $SwitchName } |
                                  Select-Object -First 1
                if ($updatedAdapter.MacAddress -eq $newMac) {
                    $macAssigned = $true
                }
            }
            catch {
                Write-Log "Failed to assign MAC $newMac to $SwitchName adapter, retrying..." -Level Warning
            }
        }
        $attempts++
    }

    if (-not $macAssigned) {
        throw "Failed to assign unique MAC address to $SwitchName adapter after $maxAttempts attempts"
    }

    return $newMac
}

function Get-RandomHostname {
    <#
    .SYNOPSIS
        Generates a random hostname (8-16 characters, alphanumeric)
    #>
    $length = Get-Random -Minimum 8 -Maximum 17
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    $hostname = -join ((1..$length) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
    return $hostname
}

function Get-NextAvailableIP {
    <#
    .SYNOPSIS
        Gets the next available IP address in the 10.0.0.x range
    #>
    $existingVMs = Get-AllVMInstancesFromRegistry
    $usedIPs = @($existingVMs | ForEach-Object { $_.InternalIP } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    for ($i = $script:StartIP; $i -le 254; $i++) {
        $testIP = "10.0.0.$i"
        if ($testIP -notin $usedIPs) {
            return $testIP
        }
    }

    throw "No available IP addresses in 10.0.0.10-254 range"
}

#endregion

#region GPU Functions

function Get-AllAvailableGPUs {
    <#
    .SYNOPSIS
        Gets all partitionable GPUs available on the host
    #>
    $partitionableGPUs = @(Get-CimInstance -Namespace 'ROOT\virtualization\v2' -ClassName Msvm_PartitionableGpu)
    if ($partitionableGPUs.Count -eq 0) {
        throw "No partitionable GPUs found on host."
    }

    $gpuList = @()
    foreach ($pg in $partitionableGPUs) {
        $dev = Get-PnpDevice | Where-Object {
            $_.DeviceID -Like "*$($pg.Name.Substring(8,16))*" -and $_.Status -eq 'OK'
        }
        if ($dev) {
            $gpuList += [pscustomobject]@{
                FriendlyName = $dev.FriendlyName
                ServiceName = $dev.Service
                InstancePath = $pg.Name
            }
        }
    }

    if ($gpuList.Count -eq 0) {
        throw "No available GPUs found."
    }

    return $gpuList
}

function Get-GpuInfo {
    <#
    .SYNOPSIS
        Gets GPU information for a specific GPU or auto-detects first available
    #>
    param([string]$Name)

    $dev = if ($Name -eq 'AUTO') {
        $pg = Get-CimInstance -Namespace 'ROOT\virtualization\v2' -ClassName Msvm_PartitionableGpu |
              Select-Object -First 1
        if (-not $pg) {
            throw "No partitionable GPU found on host."
        }
        Get-PnpDevice | Where-Object {
            $_.DeviceID -Like "*$($pg.Name.Substring(8,16))*" -and $_.Status -eq 'OK'
        }
    } else {
        Get-PnpDevice | Where-Object {
            $_.FriendlyName -eq $Name -and $_.Status -eq 'OK'
        }
    }

    if (-not $dev) {
        throw "GPU with name '$Name' not found"
    }

    return [pscustomobject]@{
        FriendlyName = $dev.FriendlyName
        ServiceName = $dev.Service
    }
}

function Select-GPUForVM {
    <#
    .SYNOPSIS
        Selects a GPU for a VM (auto-assigns if single GPU, prompts if multiple)
    #>
    param(
        [string]$VMName,
        [array]$AvailableGPUs,
        [string]$AssignedGPU
    )

    # If already assigned, return that
    if (-not [string]::IsNullOrWhiteSpace($AssignedGPU)) {
        $gpu = $AvailableGPUs | Where-Object { $_.InstancePath -eq $AssignedGPU }
        if ($gpu) {
            Write-Log "VM '$VMName' already assigned GPU: $($gpu.FriendlyName)"
            return $gpu.InstancePath
        }
    }

    # Single GPU - auto assign
    if ($AvailableGPUs.Count -eq 1) {
        Write-Log "Auto-assigning GPU: $($AvailableGPUs[0].FriendlyName)"
        return $AvailableGPUs[0].InstancePath
    }

    # Multiple GPUs - prompt user for each VM
    Write-Host "`nSelect GPU for VM '$VMName':" -ForegroundColor Yellow
    for ($i = 0; $i -lt $AvailableGPUs.Count; $i++) {
        Write-Host "  $($i+1). $($AvailableGPUs[$i].FriendlyName)"
    }
    do {
        $sel = [int](Read-Host "Select GPU (1-$($AvailableGPUs.Count))") - 1
    } while ($sel -lt 0 -or $sel -ge $AvailableGPUs.Count)

    Write-Log "Assigned GPU: $($AvailableGPUs[$sel].FriendlyName)" -Level Success
    return $AvailableGPUs[$sel].InstancePath
}

function Copy-ServiceDriver {
    <#
    .SYNOPSIS
        Copies GPU service driver to VHD
    #>
    param(
        [string]$DriveRoot,
        [string]$ServiceName
    )

    $svc = Get-CimInstance Win32_SystemDriver | Where-Object Name -eq $ServiceName
    if (-not $svc) {
        throw "Service driver '$ServiceName' not found on host."
    }

    $srcDir = Split-Path $svc.PathName -Parent
    $dest = Join-Path $DriveRoot "Windows\System32\HostDriverStore$($srcDir.Substring('C:\Windows\System32\DriverStore'.Length))"

    if (-not (Test-Path $dest)) {
        Write-Log "Copying service driver: $srcDir -> $dest"
        Copy-Item $srcDir -Destination $dest -Recurse -ErrorAction Stop
    }
}

function Copy-SignedDrivers {
    <#
    .SYNOPSIS
        Copies signed GPU drivers to VHD
    #>
    param(
        [string]$DriveRoot,
        [string]$GPUName,
        [string]$Hostname
    )

    $mods = Get-CimInstance Win32_PnPSignedDriver | Where-Object DeviceName -eq $GPUName
    foreach ($mod in $mods) {
        $ante = "\\$Hostname\ROOT\cimv2:Win32_PnPSignedDriver.DeviceID=`"$($mod.DeviceID -replace '\\','\\\\')`""
        $files = Get-CimInstance Win32_PnPSignedDriverCIMDataFile | Where-Object Antecedent -eq $ante

        foreach ($f in $files) {
            $path = ($f.Dependent -split '=' | Select-Object -Last 1).Trim('"') -replace '\\\\','\\'
            $dest = if ($path -like 'C:\Windows\System32\DriverStore\*') {
                Join-Path $DriveRoot "Windows\System32\HostDriverStore$($path.Substring('C:\Windows\System32\DriverStore'.Length))"
            } else {
                $path -replace 'C:', $DriveRoot
            }

            $destDir = Split-Path $dest -Parent
            if (-not (Test-Path $destDir)) {
                New-Item $destDir -ItemType Directory -Force | Out-Null
            }
            if (-not (Test-Path $dest)) {
                Write-Log "Copying driver file: $path"
                Copy-Item $path -Destination $destDir -Force -ErrorAction Stop
            }
        }
    }
}

function Inject-GpuDrivers {
    <#
    .SYNOPSIS
        Injects GPU drivers into a VHD file
    #>
    param(
        [string]$VHDPath,
        [array]$GPUList
    )

    $disk = $null
    $driveLetter = $null
    $partition = $null

    try {
        # Mount and assign drive letter
        Write-Log "Mounting VHD: $VHDPath"
        $disk = Mount-VHD -Path $VHDPath -Passthru -ErrorAction Stop | Get-Disk -ErrorAction Stop
        $partition = Get-Partition -DiskNumber $disk.Number -ErrorAction Stop |
                     Sort-Object Size -Descending | Select-Object -First 1
        if (-not $partition) {
            throw "No partitions found on disk $($disk.Number)"
        }

        # Check for available drive letters
        $availableLetters = @([char[]](68..90) | Where-Object {
            $_ -notin (Get-PSDrive -PSProvider FileSystem).Name
        })
        if ($availableLetters.Count -eq 0) {
            throw "No available drive letters (D-Z all in use)"
        }

        $driveLetter = $availableLetters[0]
        Write-Log "Assigning drive letter '${driveLetter}:' to partition..."
        Set-Partition -DiskNumber $disk.Number -PartitionNumber $partition.PartitionNumber `
                      -NewDriveLetter $driveLetter -ErrorAction Stop

        # Verify drive letter assignment
        Start-Sleep -Milliseconds 500
        $assignedLetter = (Get-Partition -DiskNumber $disk.Number `
                          -PartitionNumber $partition.PartitionNumber -ErrorAction Stop).DriveLetter
        if ($assignedLetter -ne $driveLetter) {
            throw "Drive letter assignment failed: expected $driveLetter, got $assignedLetter"
        }
        Write-Log "Drive letter assignment verified: ${driveLetter}:"

        # Prepare and copy drivers for all GPUs
        $root = "${driveLetter}:\"
        New-Item (Join-Path $root 'Windows\System32\HostDriverStore') -ItemType Directory `
                 -Force -ErrorAction SilentlyContinue | Out-Null

        foreach ($gpu in $GPUList) {
            Write-Log "Injecting drivers for '$($gpu.FriendlyName)'"
            Copy-ServiceDriver -DriveRoot $root -ServiceName $gpu.ServiceName
            Copy-SignedDrivers -DriveRoot $root -GPUName $gpu.FriendlyName `
                              -Hostname $env:COMPUTERNAME
        }
        Write-Log "GPU driver injection completed for $($GPUList.Count) GPU(s)" -Level Success
    }
    finally {
        # Cleanup - remove drive letter and dismount VHD
        if ($driveLetter -and $disk -and $partition) {
            try {
                Remove-PartitionAccessPath -DiskNumber $disk.Number `
                    -PartitionNumber $partition.PartitionNumber `
                    -AccessPath "${driveLetter}:" -ErrorAction Stop
                Write-Log "Drive letter removed successfully"
            }
            catch {
                Write-Log "Warning: Failed to remove drive letter: $($_.Exception.Message)" `
                         -Level Warning
            }
        }

        if ($disk) {
            # Retry dismount with backoff and verification
            $dismounted = $false
            $maxRetries = 3
            for ($retry = 0; $retry -lt $maxRetries; $retry++) {
                try {
                    Dismount-VHD -Path $VHDPath -ErrorAction Stop
                    Start-Sleep -Seconds 2

                    # Verify dismount succeeded
                    $stillMounted = Get-VHD -Path $VHDPath -ErrorAction SilentlyContinue
                    if ($stillMounted -and $stillMounted.Attached) {
                        throw "VHD still mounted after dismount command"
                    }

                    Write-Log "VHD dismounted and verified successfully"
                    $dismounted = $true
                    break
                }
                catch {
                    if ($retry -eq ($maxRetries - 1)) {
                        Write-Log "CRITICAL: Failed to dismount VHD after $maxRetries attempts: $VHDPath" `
                                 -Level Error
                        Write-Log "Error: $($_.Exception.Message)" -Level Error
                        Write-Log "Manual intervention required: Dismount-VHD -Path '$VHDPath'" -Level Error
                        throw "VHD dismount failed - template may be unusable"
                    }
                    else {
                        Write-Log "Dismount attempt $($retry + 1) failed, retrying..." -Level Warning
                        Start-Sleep -Seconds (2 * ($retry + 1))
                    }
                }
            }
        }
    }
}

#endregion

#region VM Creation Functions

function New-VMFromTemplate {
    <#
    .SYNOPSIS
        Creates a new VM from template VHDX with network adapters and GPU
    #>
    param(
        [string]$VMName,
        [string]$TemplateVHDX,
        [string]$VHDPath,
        [int64]$MemoryBytes,
        [int]$ProcessorCount,
        [string]$GPUInstancePath
    )

    # Copy template and create VM
    Write-Log "Creating VM from template: $VMName"
    Write-Log "  Copying template: $TemplateVHDX -> $VHDPath"
    Copy-Item -Path $TemplateVHDX -Destination $VHDPath -Force
    $vm = New-VM -Name $VMName -MemoryStartupBytes $MemoryBytes -VHDPath $VHDPath `
                 -Generation 2 -ErrorAction Stop

    # Configure VM settings
    Set-VM -Name $VMName -ProcessorCount $ProcessorCount -StaticMemory `
           -CheckpointType Disabled -GuestControlledCacheTypes $true `
           -LowMemoryMappedIoSpace 3GB -HighMemoryMappedIoSpace 33GB -ErrorAction Stop
    Get-VMNetworkAdapter -VMName $VMName | Remove-VMNetworkAdapter

    # Add network adapters with unique random TP-Link MACs
    foreach ($switchName in @($script:ExternalSwitch, $script:InternalSwitch)) {
        Add-VMNetworkAdapter -VMName $VMName -SwitchName $switchName -Name $switchName
        $mac = Set-VMStaticMac -VMName $VMName -SwitchName $switchName -Force
        Write-Log "$switchName adapter MAC: $mac"
    }

    # Add GPU partition adapter with specific GPU assignment (ensure only 1 GPU)
    Get-VMGpuPartitionAdapter -VMName $VMName -ErrorAction SilentlyContinue | Remove-VMGpuPartitionAdapter -ErrorAction SilentlyContinue
    if (-not [string]::IsNullOrWhiteSpace($GPUInstancePath)) {
        Add-VMGpuPartitionAdapter -VMName $VMName -InstancePath $GPUInstancePath -ErrorAction Stop
        Write-Log "VM '$VMName' created with GPU: $GPUInstancePath" -Level Success
    } else {
        Add-VMGpuPartitionAdapter -VMName $VMName -ErrorAction Stop
        Write-Log "VM '$VMName' created with GPU partition adapter (no specific GPU assigned)" -Level Warning
    }

    # Get assigned MAC addresses
    $adapters = Get-VMNetworkAdapter -VMName $VMName
    $externalMac = ($adapters | Where-Object { $_.Name -eq $script:ExternalSwitch }).MacAddress
    $internalMac = ($adapters | Where-Object { $_.Name -eq $script:InternalSwitch }).MacAddress

    return @{
        VM = $vm
        ExternalMAC = $externalMac
        InternalMAC = $internalMac
    }
}

#endregion
