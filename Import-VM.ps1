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

#region Main Execution

try {
    Write-ScriptHeader -Title "Import Existing VM"
    $LogFile = Initialize-Script -LogFile $LogFile

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

    # Auto-fix missing network adapters
    if (-not $hasExternalSwitch -or -not $hasInternalSwitch) {
        Write-Host ""
        Write-Log "VM is missing required network adapters - will add them now" -Level Warning

        # Check VM is stopped
        if ($targetVM.State -ne 'Off') {
            Write-Log "Stopping VM to add network adapters..." -Level Warning
            Stop-VM -Name $VMName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
        }

        # Add missing External adapter
        if (-not $hasExternalSwitch) {
            if (Get-VMSwitch -Name $script:ExternalSwitch -ErrorAction SilentlyContinue) {
                Add-VMNetworkAdapter -VMName $VMName -SwitchName $script:ExternalSwitch -Name $script:ExternalSwitch
                $externalMAC = Set-VMStaticMac -VMName $VMName -SwitchName $script:ExternalSwitch -Force
                Write-Log "Added External adapter with MAC: $externalMAC" -Level Success
            }
            else {
                Write-Log "External switch does not exist. Run Deploy-VM.ps1 first." -Level Warning
            }
        }

        # Add missing Internal adapter
        if (-not $hasInternalSwitch) {
            if (Get-VMSwitch -Name $script:InternalSwitch -ErrorAction SilentlyContinue) {
                Add-VMNetworkAdapter -VMName $VMName -SwitchName $script:InternalSwitch -Name $script:InternalSwitch
                $internalMAC = Set-VMStaticMac -VMName $VMName -SwitchName $script:InternalSwitch -Force
                Write-Log "Added Internal adapter with MAC: $internalMAC" -Level Success
            }
            else {
                Write-Log "Internal switch does not exist. Run Deploy-VM.ps1 first." -Level Warning
            }
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

    # Show available GPUs (actual assignment done via Set-GPU.ps1)
    Write-Host ""
    Show-AvailableGPUs | Out-Null

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
