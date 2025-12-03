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
    [Parameter(Mandatory=$true)]
    [string]$VMName,
    [string]$GPUName = "",
    [string]$LogFile = ""
)

# Load shared functions
. "$PSScriptRoot\Common.ps1"

#region Main Execution

try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  GPU Assignment Reconfiguration" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Check if running as administrator
    Test-AdministratorPrivileges

    # Initialize log file
    $LogFile = Initialize-LogFile -LogFile $LogFile -DefaultFolder "C:\VMs"
    Write-Log "Log file: $LogFile" -Level Info
    Write-Host ""

    # Check if VM exists in registry
    $vmData = Get-VMInstanceFromRegistry -VMName $VMName
    if (-not $vmData) {
        throw "VM '$VMName' not found in registry. Use Deploy-VM.ps1 to create it first."
    }

    Write-Log "Found VM in registry: $VMName" -Level Success

    # Check if VM exists in Hyper-V
    if (-not (Test-VMExists -VMName $VMName)) {
        throw "VM '$VMName' exists in registry but not in Hyper-V. The VM may have been deleted."
    }

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
    Write-Log "Detecting available GPUs..." -Level Info
    $availableGPUs = Get-AllAvailableGPUs
    Write-Log "Found $($availableGPUs.Count) GPU(s):" -Level Success
    foreach ($gpu in $availableGPUs) {
        Write-Log "  - $($gpu.FriendlyName)"
    }
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
    Write-Host "GPU Assignment Plan:" -ForegroundColor Yellow
    Write-Host "  VM: $VMName" -ForegroundColor White
    Write-Host "  Old GPU: $($vmData.GPUName)" -ForegroundColor Gray
    Write-Host "  New GPU: $($selectedGPU.FriendlyName)" -ForegroundColor Cyan
    Write-Host ""

    $confirm = Read-Host "Continue with GPU reassignment? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Log "GPU reassignment cancelled by user" -Level Warning
        exit 0
    }

    # Remove existing GPU partition adapter and add new one (atomic operation with rollback)
    Write-Host ""
    Write-Log "Reconfiguring GPU partition adapter..." -Level Info

    $existingAdapter = Get-VMGpuPartitionAdapter -VMName $VMName -ErrorAction SilentlyContinue
    $hadExistingAdapter = $null -ne $existingAdapter

    try {
        # Step 1: Remove existing adapter if present
        if ($hadExistingAdapter) {
            Write-Log "Removing existing GPU partition adapter..." -Level Info
            Remove-VMGpuPartitionAdapter -VMName $VMName -ErrorAction Stop
            Write-Log "Existing GPU partition adapter removed" -Level Success
        }

        # Step 2: Add new GPU partition adapter
        Write-Log "Adding new GPU partition adapter..." -Level Info
        Add-VMGpuPartitionAdapter -VMName $VMName -ErrorAction Stop
        Write-Log "GPU partition adapter added" -Level Success
    }
    catch {
        # Rollback: Try to restore adapter if we removed it but failed to add new one
        if ($hadExistingAdapter) {
            Write-Log "GPU swap failed, attempting to restore previous adapter..." -Level Warning
            try {
                Add-VMGpuPartitionAdapter -VMName $VMName -ErrorAction Stop
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
