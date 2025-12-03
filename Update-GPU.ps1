#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Updates GPU drivers in the template VHDX and optionally in existing VM VHDs.

.DESCRIPTION
    This script re-injects GPU drivers from the host into:
    - The template VHDX (used for creating new VMs)
    - Optionally, a specific VM's VHD
    - Optionally, all existing VM VHDs

    Use this after updating GPU drivers on the host to ensure VMs have
    the latest drivers.

.PARAMETER TemplateOnly
    Only update the template VHDX, not individual VMs.

.PARAMETER VMName
    Update GPU drivers for a specific VM. The VM must be stopped.

.PARAMETER AllVMs
    Update GPU drivers for all VMs in registry. All VMs must be stopped.

.PARAMETER VHDFolder
    Folder containing VHD files. Default: C:\VMs

.PARAMETER LogFile
    Path to log file. If not specified, creates timestamped log.

.EXAMPLE
    .\Update-GPU.ps1 -TemplateOnly
    Updates only the template VHDX with latest GPU drivers

.EXAMPLE
    .\Update-GPU.ps1 -VMName "HyperV-VM"
    Updates GPU drivers for a specific VM

.EXAMPLE
    .\Update-GPU.ps1 -AllVMs
    Updates GPU drivers for all VMs (requires all VMs to be stopped)
#>

[CmdletBinding()]
param(
    [switch]$TemplateOnly,
    [string]$VMName = "",
    [switch]$AllVMs,
    [string]$VHDFolder = "C:\VMs",
    [string]$LogFile = ""
)

# Load shared functions
. "$PSScriptRoot\Common.ps1"

#region Main Execution

try {
    Write-ScriptHeader -Title "GPU Driver Update Script"
    $LogFile = Initialize-Script -LogFile $LogFile -DefaultLogFolder $VHDFolder

    # Validate parameters
    $paramCount = @($TemplateOnly, (-not [string]::IsNullOrWhiteSpace($VMName)), $AllVMs) | Where-Object { $_ } | Measure-Object | Select-Object -ExpandProperty Count

    if ($paramCount -eq 0) {
        Write-Host "Select an option:" -ForegroundColor Yellow
        Write-Host "  1. Update template only"
        Write-Host "  2. Update specific VM"
        Write-Host "  3. Update all VMs"
        Write-Host ""
        $choice = Read-Host "Choice (1-3)"

        switch ($choice) {
            "1" { $TemplateOnly = $true }
            "2" {
                $VMName = Read-Host "Enter VM name"
                if ([string]::IsNullOrWhiteSpace($VMName)) {
                    throw "VM name is required"
                }
            }
            "3" { $AllVMs = $true }
            default { throw "Invalid choice" }
        }
    }
    elseif ($paramCount -gt 1) {
        throw "Only one of -TemplateOnly, -VMName, or -AllVMs can be specified"
    }

    # Detect GPUs
    $availableGPUs = Show-AvailableGPUs
    Write-Host ""

    # Get global settings
    $globalSettings = Get-GlobalSettingsFromRegistry
    $templateVHDX = if ($globalSettings -and $globalSettings.TemplateVHDX) {
        $globalSettings.TemplateVHDX
    } else {
        Join-Path $VHDFolder "template-with-gpu.vhdx"
    }

    # Update template VHDX (only for -TemplateOnly)
    if ($TemplateOnly) {
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  Updating Template VHDX" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""

        if (-not (Test-Path $templateVHDX)) {
            throw "Template VHDX not found: $templateVHDX"
        }

        Write-Log "Template: $templateVHDX" -Level Info

        # Check if template is in use
        try {
            $vhdInfo = Get-VHD -Path $templateVHDX -ErrorAction Stop
            if ($vhdInfo.Attached) {
                throw "Template VHDX is currently mounted/attached. Cannot update."
            }
        }
        catch {
            if ($_.Exception.Message -notlike "*not found*") {
                throw
            }
        }

        Write-Log "Injecting GPU drivers into template..." -Level Info
        Inject-GpuDrivers -VHDPath $templateVHDX -GPUList $availableGPUs
        Write-Log "Template VHDX updated successfully" -Level Success
        Write-Host ""
    }

    # Update specific VM
    if (-not [string]::IsNullOrWhiteSpace($VMName)) {
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  Updating VM: $VMName" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""

        # Check VM exists
        $vmData = Get-VMInstanceFromRegistry -VMName $VMName
        if (-not $vmData) {
            throw "VM '$VMName' not found in registry"
        }

        # Check VM is stopped
        if (Test-VMExists -VMName $VMName) {
            $vmState = Get-VMCurrentState -VMName $VMName
            if ($vmState.State -ne 'Off') {
                throw "VM '$VMName' must be stopped to update GPU drivers. Current state: $($vmState.State)"
            }
        }

        $vhdPath = $vmData.VHDPath
        if (-not (Test-Path $vhdPath)) {
            throw "VHD not found: $vhdPath"
        }

        Write-Log "VHD: $vhdPath" -Level Info
        Write-Log "Injecting GPU drivers..." -Level Info
        Inject-GpuDrivers -VHDPath $vhdPath -GPUList $availableGPUs
        Write-Log "VM '$VMName' updated successfully" -Level Success
        Write-Host ""
    }

    # Update all VMs
    if ($AllVMs) {
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host "  Updating All VMs" -ForegroundColor Yellow
        Write-Host "========================================" -ForegroundColor Yellow
        Write-Host ""

        $allVMData = Get-AllVMInstancesFromRegistry
        if ($allVMData.Count -eq 0) {
            Write-Log "No VMs found in registry" -Level Warning
        }
        else {
            Write-Log "Found $($allVMData.Count) VM(s) to update" -Level Info

            # First, verify all VMs are stopped
            foreach ($vm in $allVMData) {
                if (Test-VMExists -VMName $vm.Name) {
                    $vmState = Get-VMCurrentState -VMName $vm.Name
                    if ($vmState.State -ne 'Off') {
                        throw "VM '$($vm.Name)' must be stopped. Current state: $($vmState.State). Stop all VMs first."
                    }
                }
            }

            $successCount = 0
            $failCount = 0

            foreach ($vm in $allVMData) {
                Write-Host ""
                Write-Log "Updating VM: $($vm.Name)" -Level Info

                if (-not (Test-Path $vm.VHDPath)) {
                    Write-Log "VHD not found: $($vm.VHDPath)" -Level Warning
                    $failCount++
                    continue
                }

                try {
                    Inject-GpuDrivers -VHDPath $vm.VHDPath -GPUList $availableGPUs
                    Write-Log "VM '$($vm.Name)' updated successfully" -Level Success
                    $successCount++
                }
                catch {
                    Write-Log "Failed to update VM '$($vm.Name)': $($_.Exception.Message)" -Level Error
                    $failCount++
                }
            }

            Write-Host ""
            Write-Log "Update complete: $successCount succeeded, $failCount failed" -Level $(if ($failCount -eq 0) { 'Success' } else { 'Warning' })
        }
    }

    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  GPU Driver Update Complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "GPU drivers from host have been injected into the VHD(s)." -ForegroundColor Gray
    Write-Host "VMs will use these drivers when started." -ForegroundColor Gray
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
