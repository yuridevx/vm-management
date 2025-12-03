#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Resets a single Hyper-V VM by recreating it from the template VHDX.

.DESCRIPTION
    This script completely recreates a VM from the GPU-enabled template VHDX,
    preserving its configuration from the registry (IP address, hostname, GPU assignment).

    Use cases:
    - Reset a corrupted VM to clean state
    - Apply template updates to the VM
    - Troubleshoot VM-specific issues
    - Recover from configuration errors

.PARAMETER VMName
    Name of the VM to recreate. Required.

.PARAMETER VMUsername
    Username for VM login via PowerShell Direct. Default: home

.PARAMETER VMPassword
    Password for VM login via PowerShell Direct. Default: home

.PARAMETER Memory
    Amount of memory in bytes. If not specified, uses value from registry.

.PARAMETER CPU
    Number of virtual CPUs. If not specified, uses value from registry.

.PARAMETER HeartbeatTimeout
    Timeout in seconds to wait for VM heartbeat. Default: 90

.PARAMETER LogFile
    Path to log file. If not specified, creates timestamped log.

.EXAMPLE
    .\Reset-VM.ps1 -VMName "HyperV-VM"
    Resets VM from template with existing configuration

.EXAMPLE
    .\Reset-VM.ps1 -VMName "HyperV-VM" -Memory 8GB -CPU 8
    Resets VM with updated resource allocation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$VMName,
    [string]$VMUsername = "home",
    [string]$VMPassword = "home",
    [int64]$Memory = 0,
    [int]$CPU = 0,
    [int]$HeartbeatTimeout = 90,
    [string]$LogFile = ""
)

# Load shared functions
. "$PSScriptRoot\Common.ps1"

$MAX_CONFIG_RETRIES = 3

#region Main Execution

try {
    Write-ScriptHeader -Title "VM Recreation Script"
    $LogFile = Initialize-Script -LogFile $LogFile

    # Get VM from registry (don't require Hyper-V existence - we're recreating it)
    $vmData = Get-VMInstanceFromRegistry -VMName $VMName
    if (-not $vmData) {
        throw "VM '$VMName' not found in registry. Use Deploy-VM.ps1 to create it first."
    }
    Write-Log "Found VM in registry: $VMName" -Level Success

    # Get global settings for template path
    $globalSettings = Get-GlobalSettingsFromRegistry
    if (-not $globalSettings -or -not $globalSettings.TemplateVHDX) {
        throw "Template VHDX path not found in registry. Run Deploy-VM.ps1 first."
    }

    $templateVHDX = $globalSettings.TemplateVHDX
    if (-not (Test-Path $templateVHDX)) {
        throw "Template VHDX not found: $templateVHDX"
    }

    Write-Log "Template VHDX: $templateVHDX" -Level Success

    # Validate template integrity
    try {
        $vhdInfo = Get-VHD -Path $templateVHDX -ErrorAction Stop
        Write-Log "Template size: $([Math]::Round($vhdInfo.Size/1GB, 2)) GB" -Level Success
    }
    catch {
        throw "Template VHDX integrity check failed: $($_.Exception.Message)"
    }

    # Determine resources to use
    $memoryToUse = if ($Memory -gt 0) { $Memory } elseif ($vmData.Memory) { $vmData.Memory } else { $globalSettings.DefaultMemory }
    $cpuToUse = if ($CPU -gt 0) { $CPU } elseif ($vmData.CPU) { $vmData.CPU } else { $globalSettings.DefaultCPU }

    if (-not $memoryToUse -or -not $cpuToUse) {
        throw "Memory or CPU not specified and not found in registry."
    }

    # Detect GPUs
    $availableGPUs = Show-AvailableGPUs

    # Show recreation plan
    Write-Host ""
    Write-Host "Recreation: $VMName (Memory: $($memoryToUse / 1MB)MB, CPUs: $cpuToUse)" -ForegroundColor Yellow
    Write-Host "WARNING: This will DELETE and RECREATE the VM!" -ForegroundColor Red
    Write-Host ""

    if (-not (Request-UserConfirmation -Message "Continue with recreation?" -CancelMessage "Recreation cancelled by user")) {
        exit 0
    }

    # Create credentials
    $credential = New-VMCredential -Username $VMUsername -Password $VMPassword

    # Step 1: Remove existing VM
    Write-Host ""
    Write-Log "Step 1: Removing existing VM..." -Level Warning

    if (Test-VMExists -VMName $VMName) {
        $success = Remove-VMCompletely -VMName $VMName -VHDPath $vmData.VHDPath -IncludeVHD
        if ($success) {
            Write-Log "VM removed successfully" -Level Success
        } else {
            throw "Failed to remove existing VM"
        }
    } else {
        Write-Log "VM does not exist in Hyper-V, will create from template" -Level Warning
    }

    # Step 2: Recreate VM from template
    Write-Host ""
    Write-Log "Step 2: Recreating VM from template..." -Level Info

    # Select GPU (use existing assignment if available)
    $assignedGPU = Select-GPUForVM -VMName $VMName -AvailableGPUs $availableGPUs -AssignedGPU $vmData.AssignedGPU

    # Create VM from template
    $vmResult = New-VMFromTemplate -VMName $VMName `
                                   -TemplateVHDX $templateVHDX `
                                   -VHDPath $vmData.VHDPath `
                                   -MemoryBytes $memoryToUse `
                                   -ProcessorCount $cpuToUse `
                                   -GPUInstancePath $assignedGPU

    Write-Log "  New External MAC: $($vmResult.ExternalMAC)" -Level Success
    Write-Log "  New Internal MAC: $($vmResult.InternalMAC)" -Level Success

    # Step 3: Configure network
    Write-Host ""
    Write-Log "Step 3: Configuring network..." -Level Info

    # Generate new random hostname
    $newHostname = Get-RandomHostname
    Write-Log "  Generated hostname: $newHostname" -Level Info

    Write-Log "Starting VM for configuration..."
    $vmStarted = Start-VMSafely -VMName $VMName
    $configured = $false

    if ($vmStarted) {
        $heartbeatReady = Wait-VMHeartbeat -VMName $VMName -TimeoutSeconds $HeartbeatTimeout

        if ($heartbeatReady) {
            $configured = Configure-VMNetwork -VMName $VMName `
                                             -InternalIP $vmData.InternalIP `
                                             -Hostname $newHostname `
                                             -Credential $credential `
                                             -InternalMAC $vmResult.InternalMAC `
                                             -MaxRetries $MAX_CONFIG_RETRIES
        }
    }

    # Stop VM after configuration
    Write-Log "Shutting down VM after configuration..."
    Stop-VMSafely -VMName $VMName -WaitForShutdown | Out-Null

    # Get GPU friendly name
    $gpuFriendlyName = ($availableGPUs | Where-Object { $_.InstancePath -eq $assignedGPU }).FriendlyName

    # Update registry (need to remove old entry and create new one with new GUID)
    $newVMGuid = $vmResult.VM.VMId.Guid
    $oldVMGuid = $vmData.ID

    # Remove old registry entry if GUID changed
    if ($oldVMGuid -and $oldVMGuid -ne $newVMGuid) {
        Remove-VMInstanceFromRegistry -VMID $oldVMGuid | Out-Null
    }

    # Only store what can't be inferred from VM state
    $updatedData = @{
        InternalIP = $vmData.InternalIP
        Configured = $configured
    }

    Save-VMInstanceToRegistry -VMID $newVMGuid -VMData $updatedData
    Write-Log "Registry updated" -Level Success

    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Recreation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  VM: $VMName" -ForegroundColor White
    Write-Host "  ID: $($vmResult.VM.VMId.Guid)" -ForegroundColor Gray
    Write-Host "  IP: $($vmData.InternalIP)" -ForegroundColor Gray
    Write-Host "  Hostname: $newHostname" -ForegroundColor Gray
    Write-Host "  External MAC: $($vmResult.ExternalMAC)" -ForegroundColor Gray
    Write-Host "  Internal MAC: $($vmResult.InternalMAC)" -ForegroundColor Gray
    Write-Host "  GPU: $gpuFriendlyName" -ForegroundColor Cyan
    Write-Host "  Configured: $(if ($configured) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($configured) { 'Green' } else { 'Yellow' })
    Write-Host ""

    if ($configured) {
        Write-Log "IMPORTANT: VM may require reboot for hostname changes to take effect" -Level Warning
    }
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Log "CRITICAL ERROR: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    Write-Host ""
    exit 1
}

#endregion
