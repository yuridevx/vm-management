#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Reconfigures GPU assignment for a single Hyper-V VM.

.DESCRIPTION
    This script allows you to change the GPU partition adapter assignment for a VM.
    The VM must be stopped to change GPU assignment.

    Use cases:
    - Switch a VM to use a different GPU
    - Reassign GPU after hardware changes
    - Troubleshoot GPU-related issues

.PARAMETER VMName
    Name of the VM to reconfigure. Required.

.PARAMETER GPUName
    Name of the GPU to assign. If not specified, shows interactive selection.

.PARAMETER LogFile
    Path to log file. If not specified, creates timestamped log.

.EXAMPLE
    .\Set-GPU.ps1 -VMName "HyperV-VM"
    Shows interactive GPU selection for the VM

.EXAMPLE
    .\Set-GPU.ps1 -VMName "HyperV-VM" -GPUName "NVIDIA GeForce RTX 4090"
    Assigns the specified GPU to the VM
#>

[CmdletBinding()]
param(
    [string]$VMName = "",
    [string]$GPUName = "",
    [string]$LogFile = ""
)

# Load shared functions
. "$PSScriptRoot\Common.ps1"

# Select VM if not specified
if ([string]::IsNullOrWhiteSpace($VMName)) {
    $VMName = Select-ManagedVM
    if (-not $VMName) { exit 0 }
}

#region Main Execution

try {
    Write-ScriptHeader -Title "GPU Assignment Reconfiguration"
    $LogFile = Initialize-Script -LogFile $LogFile

    # Validate VM exists in both registry and Hyper-V
    $vmData = Assert-VMExistsInRegistryAndHyperV -VMName $VMName

    # Check VM is stopped
    $vmState = Get-VMCurrentState -VMName $VMName
    if ($vmState.State -ne 'Off') {
        throw "VM must be stopped to change GPU assignment. Current state: $($vmState.State)"
    }

    Write-Log "VM is stopped - ready for GPU reconfiguration" -Level Success

    # Show current GPU assignment
    Write-Host ""
    Write-Host "Current GPU Assignment:" -ForegroundColor Yellow
    if ($vmData.GPUName) {
        Write-Host "  GPU: $($vmData.GPUName)" -ForegroundColor Gray
    } else {
        Write-Host "  GPU: (not recorded)" -ForegroundColor Gray
    }
    Write-Host ""

    # Detect available GPUs
    $availableGPUs = Show-AvailableGPUs
    Write-Host ""

    # Select GPU
    $selectedGPU = $null

    if (-not [string]::IsNullOrWhiteSpace($GPUName)) {
        # Find GPU by name
        $selectedGPU = $availableGPUs | Where-Object { $_.FriendlyName -eq $GPUName }
        if (-not $selectedGPU) {
            throw "GPU '$GPUName' not found. Available GPUs: $($availableGPUs.FriendlyName -join ', ')"
        }
        Write-Log "Selected GPU: $($selectedGPU.FriendlyName)" -Level Success
    }
    else {
        # Interactive selection
        if ($availableGPUs.Count -eq 1) {
            $selectedGPU = $availableGPUs[0]
            Write-Log "Auto-selecting only available GPU: $($selectedGPU.FriendlyName)" -Level Info
        }
        else {
            Write-Host "Select GPU for VM '$VMName':" -ForegroundColor Yellow
            for ($i = 0; $i -lt $availableGPUs.Count; $i++) {
                $marker = if ($availableGPUs[$i].InstancePath -eq $vmData.AssignedGPU) { " (current)" } else { "" }
                Write-Host "  $($i+1). $($availableGPUs[$i].FriendlyName)$marker"
            }
            Write-Host ""

            do {
                $sel = Read-Host "Select GPU (1-$($availableGPUs.Count))"
                $selIndex = [int]$sel - 1
            } while ($selIndex -lt 0 -or $selIndex -ge $availableGPUs.Count)

            $selectedGPU = $availableGPUs[$selIndex]
        }
    }

    # Check if same GPU is selected
    if ($selectedGPU.InstancePath -eq $vmData.AssignedGPU) {
        Write-Log "Selected GPU is already assigned to this VM. No changes needed." -Level Warning
        exit 0
    }

    Write-Host ""
    Write-Log "Reassigning GPU: $($vmData.GPUName) -> $($selectedGPU.FriendlyName)" -Level Info

    # Remove existing GPU partition adapter and add new one (atomic operation with rollback)
    Write-Host ""
    Write-Log "Reconfiguring GPU partition adapter..." -Level Info

    $existingAdapters = @(Get-VMGpuPartitionAdapter -VMName $VMName -ErrorAction SilentlyContinue)
    $hadExistingAdapter = $existingAdapters.Count -gt 0
    $previousInstancePath = if ($hadExistingAdapter) { $existingAdapters[0].InstancePath } else { $null }

    try {
        # Step 1: Remove ALL existing adapters (ensure only 1 GPU)
        if ($hadExistingAdapter) {
            Write-Log "Removing existing GPU partition adapter(s)..." -Level Info
            $existingAdapters | Remove-VMGpuPartitionAdapter -ErrorAction Stop
            Write-Log "Existing GPU partition adapter(s) removed" -Level Success
        }

        # Step 2: Add new GPU partition adapter with specific GPU assignment
        Write-Log "Adding new GPU partition adapter..." -Level Info
        Add-VMGpuPartitionAdapter -VMName $VMName -InstancePath $selectedGPU.InstancePath -ErrorAction Stop
        Write-Log "GPU partition adapter added with GPU: $($selectedGPU.FriendlyName)" -Level Success
    }
    catch {
        # Rollback: Try to restore adapter if we removed it but failed to add new one
        if ($hadExistingAdapter) {
            Write-Log "GPU swap failed, attempting to restore previous adapter..." -Level Warning
            try {
                if ($previousInstancePath) {
                    Add-VMGpuPartitionAdapter -VMName $VMName -InstancePath $previousInstancePath -ErrorAction Stop
                } else {
                    Add-VMGpuPartitionAdapter -VMName $VMName -ErrorAction Stop
                }
                Write-Log "Previous GPU adapter restored" -Level Warning
            }
            catch {
                Write-Log "CRITICAL: Failed to restore GPU adapter. VM may need manual GPU configuration." -Level Error
            }
        }
        throw "Failed to reconfigure GPU partition adapter: $($_.Exception.Message)"
    }

    # Update registry
    $vmData.AssignedGPU = $selectedGPU.InstancePath
    $vmData.GPUName = $selectedGPU.FriendlyName

    Save-VMInstanceToRegistry -VMID $vmData.ID -VMData $vmData
    Write-Log "Registry updated with new GPU assignment" -Level Success

    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  GPU Reassignment Complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  VM: $VMName" -ForegroundColor White
    Write-Host "  New GPU: $($selectedGPU.FriendlyName)" -ForegroundColor Cyan
    Write-Host ""
    Write-Log "GPU reassignment completed successfully" -Level Success
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
