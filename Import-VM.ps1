#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Imports an existing Hyper-V VM into the registry for management by other scripts.

.DESCRIPTION
    This script registers an existing Hyper-V VM (not created by Deploy-VM.ps1)
    into the registry so it can be managed by Set-Network, Set-GPU, Reset-VM, etc.

    The script will:
    - Detect the VM's current configuration (memory, CPU, VHD, MAC addresses)
    - Prompt for missing information (IP, hostname, GPU)
    - Save all data to the registry

.PARAMETER VMName
    Name of the existing Hyper-V VM to import. If not specified, shows list of VMs.

.PARAMETER InternalIP
    IP address to assign/record for the VM. If not specified, auto-assigns from available range.

.PARAMETER Hostname
    Hostname for the VM. If not specified, generates random hostname.

.PARAMETER LogFile
    Path to log file. If not specified, creates timestamped log.

.EXAMPLE
    .\Import-VM.ps1
    Shows list of VMs not in registry and prompts for selection

.EXAMPLE
    .\Import-VM.ps1 -VMName "ExistingVM"
    Imports specific VM into registry

.EXAMPLE
    .\Import-VM.ps1 -VMName "ExistingVM" -InternalIP "10.0.0.50" -Hostname "myserver"
    Imports VM with specific IP and hostname
#>

[CmdletBinding()]
param(
    [string]$VMName = "",
    [string]$InternalIP = "",
    [string]$LogFile = ""
)

# Load shared functions
. "$PSScriptRoot\Common.ps1"

#region Helper Functions

function Get-UnmanagedVMs {
    <#
    .SYNOPSIS
        Gets list of Hyper-V VMs not in our registry
    #>
    $allHyperVVMs = Get-VM -ErrorAction SilentlyContinue
    $managedVMs = Get-AllVMInstancesFromRegistry

    $unmanagedVMs = @()
    foreach ($vm in $allHyperVVMs) {
        $isManaged = $managedVMs | Where-Object { $_.Name -eq $vm.Name }
        if (-not $isManaged) {
            $unmanagedVMs += $vm
        }
    }

    return $unmanagedVMs
}

# Get-NextAvailableIP is now in Common.ps1

#endregion

#region Main Execution

try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  Import Existing VM" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Check if running as administrator
    Test-AdministratorPrivileges

    # Initialize log file
    $LogFile = Initialize-LogFile -LogFile $LogFile -DefaultFolder "C:\VMs"
    Write-Log "Log file: $LogFile" -Level Info
    Write-Host ""

    # Get VM to import
    $targetVM = $null

    if ([string]::IsNullOrWhiteSpace($VMName)) {
        # Show list of unmanaged VMs
        $unmanagedVMs = Get-UnmanagedVMs

        if ($unmanagedVMs.Count -eq 0) {
            Write-Log "No unmanaged VMs found. All Hyper-V VMs are already in registry." -Level Warning
            exit 0
        }

        Write-Host "Unmanaged VMs (not in registry):" -ForegroundColor Yellow
        Write-Host ""
        for ($i = 0; $i -lt $unmanagedVMs.Count; $i++) {
            $vm = $unmanagedVMs[$i]
            $state = $vm.State
            $mem = [Math]::Round($vm.MemoryStartup / 1MB, 0)
            Write-Host "  $($i+1). $($vm.Name)" -ForegroundColor White -NoNewline
            Write-Host " (State: $state, Memory: ${mem}MB, CPUs: $($vm.ProcessorCount))" -ForegroundColor Gray
        }
        Write-Host ""

        do {
            $sel = Read-Host "Select VM to import (1-$($unmanagedVMs.Count))"
            $selIndex = -1
            if ($sel -match '^\d+$') {
                $selIndex = [int]$sel - 1
            }
        } while ($selIndex -lt 0 -or $selIndex -ge $unmanagedVMs.Count)

        $targetVM = $unmanagedVMs[$selIndex]
        $VMName = $targetVM.Name
    }
    else {
        # Check if VM exists in Hyper-V
        $targetVM = Get-VM -Name $VMName -ErrorAction SilentlyContinue
        if (-not $targetVM) {
            throw "VM '$VMName' not found in Hyper-V"
        }

        # Check if already managed
        $existing = Get-VMInstanceFromRegistry -VMName $VMName
        if ($existing) {
            throw "VM '$VMName' is already in registry. No import needed."
        }
    }

    Write-Log "Selected VM: $VMName" -Level Success
    Write-Host ""

    # Get VM details from Hyper-V
    Write-Log "Reading VM configuration from Hyper-V..." -Level Info

    $vmMemory = $targetVM.MemoryStartup
    $vmCPU = $targetVM.ProcessorCount
    $vmID = $targetVM.VMId.Guid

    # Get VHD path
    $vhdPath = ""
    $hardDrives = Get-VMHardDiskDrive -VMName $VMName -ErrorAction SilentlyContinue
    if ($hardDrives -and $hardDrives.Count -gt 0) {
        $vhdPath = $hardDrives[0].Path
        Write-Log "  VHD: $vhdPath"
    }
    else {
        Write-Log "  VHD: (none found)" -Level Warning
    }

    Write-Log "  Memory: $([Math]::Round($vmMemory / 1MB, 0)) MB"
    Write-Log "  CPUs: $vmCPU"
    Write-Log "  ID: $vmID"

    # Get MAC addresses and check network adapter setup
    $adapters = Get-VMNetworkAdapter -VMName $VMName -ErrorAction SilentlyContinue
    $externalMAC = ""
    $internalMAC = ""
    $hasExternalSwitch = $false
    $hasInternalSwitch = $false
    $needsMacReplacement = @()

    foreach ($adapter in $adapters) {
        if ($adapter.SwitchName -eq $script:ExternalSwitch) {
            $externalMAC = $adapter.MacAddress
            $hasExternalSwitch = $true
            # Check if adapter is configured for dynamic MAC (not static)
            if ($adapter.DynamicMacAddressEnabled) {
                Write-Log "  External MAC: $externalMAC (dynamic - will replace)" -Level Warning
                $needsMacReplacement += @{ SwitchName = $adapter.SwitchName; Type = "External" }
            }
            else {
                Write-Log "  External MAC: $externalMAC"
            }
        }
        elseif ($adapter.SwitchName -eq $script:InternalSwitch) {
            $internalMAC = $adapter.MacAddress
            $hasInternalSwitch = $true
            # Check if adapter is configured for dynamic MAC (not static)
            if ($adapter.DynamicMacAddressEnabled) {
                Write-Log "  Internal MAC: $internalMAC (dynamic - will replace)" -Level Warning
                $needsMacReplacement += @{ SwitchName = $adapter.SwitchName; Type = "Internal" }
            }
            else {
                Write-Log "  Internal MAC: $internalMAC"
            }
        }
        else {
            Write-Log "  Other adapter: $($adapter.SwitchName) (MAC: $($adapter.MacAddress))" -Level Warning
        }
    }

    # Replace dynamic MACs with random TP-Link MACs
    if ($needsMacReplacement.Count -gt 0) {
        # Check VM is stopped
        if ($targetVM.State -ne 'Off') {
            Write-Log "Stopping VM to replace dynamic MACs..." -Level Warning
            Stop-VM -Name $VMName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
        }

        foreach ($adapterInfo in $needsMacReplacement) {
            $mac = Set-VMStaticMac -VMName $VMName -SwitchName $adapterInfo.SwitchName -Force
            if ($adapterInfo.Type -eq "External") {
                $externalMAC = $mac
            }
            else {
                $internalMAC = $mac
            }
            Write-Log "  Replaced $($adapterInfo.Type) adapter with random MAC: $mac" -Level Success
        }
    }

    # Warn about missing network setup
    if (-not $hasExternalSwitch -or -not $hasInternalSwitch) {
        Write-Host ""
        Write-Host "WARNING: VM is missing required network adapters!" -ForegroundColor Yellow
        if (-not $hasExternalSwitch) {
            Write-Host "  - Missing: External switch adapter" -ForegroundColor Yellow
        }
        if (-not $hasInternalSwitch) {
            Write-Host "  - Missing: Internal switch adapter" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "Network configuration (Set-Network.ps1) requires both adapters." -ForegroundColor Gray
        Write-Host ""

        $setupNetwork = Read-Host "Add missing network adapters now? (Y/N)"
        if ($setupNetwork -match '^[Yy]') {
            # Check VM is stopped
            if ($targetVM.State -ne 'Off') {
                Write-Log "Stopping VM to add network adapters..." -Level Warning
                Stop-VM -Name $VMName -Force -ErrorAction Stop
                Start-Sleep -Seconds 2
            }

            # Ensure switches exist
            if (-not (Get-VMSwitch -Name $script:ExternalSwitch -ErrorAction SilentlyContinue)) {
                Write-Log "External switch '$($script:ExternalSwitch)' does not exist. Create it first using Deploy-VM.ps1" -Level Error
            }
            else {
                if (-not $hasExternalSwitch) {
                    Add-VMNetworkAdapter -VMName $VMName -SwitchName $script:ExternalSwitch -Name $script:ExternalSwitch
                    $mac = Set-VMStaticMac -VMName $VMName -SwitchName $script:ExternalSwitch -Force
                    $externalMAC = $mac
                    Write-Log "Added External adapter with MAC: $mac" -Level Success
                }
            }

            if (-not (Get-VMSwitch -Name $script:InternalSwitch -ErrorAction SilentlyContinue)) {
                Write-Log "Internal switch '$($script:InternalSwitch)' does not exist. Create it first using Deploy-VM.ps1" -Level Error
            }
            else {
                if (-not $hasInternalSwitch) {
                    Add-VMNetworkAdapter -VMName $VMName -SwitchName $script:InternalSwitch -Name $script:InternalSwitch
                    $mac = Set-VMStaticMac -VMName $VMName -SwitchName $script:InternalSwitch -Force
                    $internalMAC = $mac
                    Write-Log "Added Internal adapter with MAC: $mac" -Level Success
                }
            }
        }
        else {
            Write-Log "Skipping network adapter setup. Set-Network.ps1 will not work." -Level Warning
        }
    }

    # Check for GPU adapter
    $gpuAdapter = Get-VMGpuPartitionAdapter -VMName $VMName -ErrorAction SilentlyContinue
    $hasGPU = $null -ne $gpuAdapter
    Write-Log "  GPU Adapter: $(if ($hasGPU) { 'Yes' } else { 'No' })"

    Write-Host ""

    # Determine IP address
    if ([string]::IsNullOrWhiteSpace($InternalIP)) {
        $InternalIP = Get-NextAvailableIP
        Write-Log "Auto-assigned IP: $InternalIP" -Level Info
    }
    else {
        Write-Log "Using specified IP: $InternalIP" -Level Info
    }

    # Detect GPUs and assign
    Write-Host ""
    Write-Log "Detecting available GPUs..." -Level Info
    $availableGPUs = Get-AllAvailableGPUs
    $assignedGPU = ""
    $gpuName = ""

    if ($availableGPUs.Count -gt 0) {
        Write-Log "Found $($availableGPUs.Count) GPU(s):" -Level Success
        foreach ($gpu in $availableGPUs) {
            Write-Log "  - $($gpu.FriendlyName)"
        }

        if ($availableGPUs.Count -eq 1) {
            $assignedGPU = $availableGPUs[0].InstancePath
            $gpuName = $availableGPUs[0].FriendlyName
            Write-Log "Auto-assigned GPU: $gpuName" -Level Info
        }
        else {
            Write-Host ""
            Write-Host "Select GPU to assign:" -ForegroundColor Yellow
            for ($i = 0; $i -lt $availableGPUs.Count; $i++) {
                Write-Host "  $($i+1). $($availableGPUs[$i].FriendlyName)"
            }
            Write-Host "  0. Skip GPU assignment"
            Write-Host ""

            $gpuSel = Read-Host "Select GPU (0-$($availableGPUs.Count))"
            $gpuIndex = -1
            if ($gpuSel -match '^\d+$') {
                $gpuIndex = [int]$gpuSel - 1
            }

            if ($gpuIndex -ge 0 -and $gpuIndex -lt $availableGPUs.Count) {
                $assignedGPU = $availableGPUs[$gpuIndex].InstancePath
                $gpuName = $availableGPUs[$gpuIndex].FriendlyName
            }
        }
    }
    else {
        Write-Log "No GPUs detected" -Level Warning
    }

    # Show import plan
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  Import Plan" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "VM Name: $VMName" -ForegroundColor White
    Write-Host "VHD Path: $vhdPath" -ForegroundColor Gray
    Write-Host "Memory: $([Math]::Round($vmMemory / 1MB, 0)) MB" -ForegroundColor Gray
    Write-Host "CPUs: $vmCPU" -ForegroundColor Gray
    Write-Host "Internal IP: $InternalIP" -ForegroundColor Gray
    Write-Host "GPU: $(if ($gpuName) { $gpuName } else { '(none)' })" -ForegroundColor $(if ($gpuName) { 'Cyan' } else { 'Gray' })
    Write-Host "(MACs and hostname will be generated on first Set-Network run)" -ForegroundColor DarkGray
    Write-Host ""

    $confirm = Read-Host "Import this VM to registry? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Log "Import cancelled by user" -Level Warning
        exit 0
    }

    # Save to registry
    Write-Host ""
    Write-Log "Saving VM to registry..." -Level Info

    # Only store what can't be inferred from VM state
    $vmData = @{
        InternalIP = $InternalIP
        Configured = $false
    }

    Save-VMInstanceToRegistry -VMID $vmID -VMData $vmData
    Write-Log "VM imported to registry successfully" -Level Success

    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Import Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "VM '$VMName' is now managed. You can use:" -ForegroundColor White
    Write-Host "  - Set-Network.ps1 -VMName `"$VMName`"  (configure IP/hostname)" -ForegroundColor Gray
    Write-Host "  - Set-GPU.ps1 -VMName `"$VMName`"      (change GPU assignment)" -ForegroundColor Gray
    Write-Host "  - Reset-VM.ps1 -VMName `"$VMName`"     (recreate from template)" -ForegroundColor Gray
    Write-Host "  - Update-GPU.ps1 -VMName `"$VMName`"   (update GPU drivers)" -ForegroundColor Gray
    Write-Host ""

    if (-not $vmData.Configured) {
        Write-Log "TIP: Run Set-Network.ps1 to configure the VM's IP and hostname" -Level Warning
    }
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Log "ERROR: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    Write-Host ""
    exit 1
}

#endregion
