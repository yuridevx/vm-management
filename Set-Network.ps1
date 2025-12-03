#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Reconfigures network settings for a single Hyper-V VM.

.DESCRIPTION
    This script reconfigures network settings (IP address and hostname) for a VM
    using PowerShell Direct. It reads the VM configuration from registry and applies
    the stored or new network settings.

.PARAMETER VMName
    Name of the VM to reconfigure. Required.

.PARAMETER NewIP
    New IP address to assign. If not specified, uses the IP from registry.

.PARAMETER NewHostname
    New hostname to assign. If not specified, uses the hostname from registry.

.PARAMETER VMUsername
    Username for VM login via PowerShell Direct. Default: home

.PARAMETER VMPassword
    Password for VM login via PowerShell Direct. Default: home

.PARAMETER KeepRunning
    Keep VM running after reconfiguration. By default, VM is stopped after reconfiguration.

.PARAMETER MaxRetries
    Maximum number of retry attempts for network configuration. Default: 3

.PARAMETER HeartbeatTimeout
    Timeout in seconds to wait for VM heartbeat. Default: 90

.PARAMETER LogFile
    Path to log file. If not specified, creates timestamped log.

.EXAMPLE
    .\Set-Network.ps1 -VMName "HyperV-VM"
    Reconfigures VM network using stored settings

.EXAMPLE
    .\Set-Network.ps1 -VMName "HyperV-VM" -NewIP "10.0.0.50" -NewHostname "myserver"
    Reconfigures VM with new IP and hostname

.EXAMPLE
    .\Set-Network.ps1 -VMName "HyperV-VM" -KeepRunning
    Reconfigures VM and keeps it running
#>

[CmdletBinding()]
param(
    [string]$VMName = "",
    [string]$NewIP = "",
    [string]$NewHostname = "",
    [string]$VMUsername = "home",
    [string]$VMPassword = "home",
    [switch]$KeepRunning,
    [int]$MaxRetries = 3,
    [int]$HeartbeatTimeout = 90,
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
    Write-ScriptHeader -Title "VM Network Reconfiguration"
    $LogFile = Initialize-Script -LogFile $LogFile

    # Validate VM exists in both registry and Hyper-V
    $vmData = Assert-VMExistsInRegistryAndHyperV -VMName $VMName

    # Check and fix network adapters, generate new MACs
    $macResult = Repair-VMNetworkAdapters -VMName $VMName -GenerateNewMACs
    $externalMac = $macResult.ExternalMAC
    $internalMac = $macResult.InternalMAC

    # Generate new hostname (always random) or use provided one
    $targetHostname = if ([string]::IsNullOrWhiteSpace($NewHostname)) { Get-RandomHostname } else { $NewHostname }
    Write-Log "  Hostname: $targetHostname" -Level Success

    # Determine IP to use
    $targetIP = if ([string]::IsNullOrWhiteSpace($NewIP)) { $vmData.InternalIP } else { $NewIP }

    # Validate IP format
    if ($targetIP -notmatch '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        throw "Invalid IP address format: $targetIP"
    }
    # Validate IP octets are in valid range (0-255)
    $octets = $targetIP -split '\.'
    foreach ($octet in $octets) {
        if ([int]$octet -lt 0 -or [int]$octet -gt 255) {
            throw "Invalid IP address (octet out of range): $targetIP"
        }
    }

    Write-Host ""
    Write-Log "Reconfiguring: IP=$targetIP, Hostname=$targetHostname" -Level Info

    # Create credential object
    $credential = New-VMCredential -Username $VMUsername -Password $VMPassword

    # Get current VM state
    $currentState = Get-VMCurrentState -VMName $VMName
    Write-Log "Current VM state: $($currentState.State)" -Level Info

    $wasRunning = $currentState.State -eq 'Running'
    $startedByScript = $false

    # Start VM if not running
    if (-not $wasRunning) {
        Write-Log "Starting VM for reconfiguration..." -Level Info
        if (-not (Start-VMSafely -VMName $VMName)) {
            throw "Failed to start VM"
        }
        $startedByScript = $true
    }

    # Wait for heartbeat
    Write-Log "Waiting for VM heartbeat..." -Level Info
    if (-not (Wait-VMHeartbeat -VMName $VMName -TimeoutSeconds $HeartbeatTimeout)) {
        throw "VM heartbeat timeout"
    }

    # Configure network
    Write-Log "Configuring network using MAC: $internalMac..." -Level Info
    $configured = Configure-VMNetwork -VMName $VMName `
                                     -InternalIP $targetIP `
                                     -Hostname $targetHostname `
                                     -Credential $credential `
                                     -InternalMAC $internalMac `
                                     -MaxRetries $MaxRetries

    if ($configured) {
        Write-Log "Network configuration successful" -Level Success

        # Update registry with new IP only (MACs and hostname are generated fresh each time)
        $vmData.InternalIP = $targetIP
        $vmData.Configured = $true

        Save-VMInstanceToRegistry -VMID $vmData.ID -VMData $vmData
        Write-Log "Registry updated" -Level Success
    }
    else {
        Write-Log "Network configuration failed" -Level Error
    }

    # Stop VM if we started it and KeepRunning is not set
    if ($startedByScript -and -not $KeepRunning) {
        Write-Log "Stopping VM..." -Level Info
        Stop-VMSafely -VMName $VMName -WaitForShutdown | Out-Null
    }
    elseif ($KeepRunning) {
        Write-Log "Keeping VM running as requested" -Level Info
    }

    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Reconfiguration Complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  VM: $VMName" -ForegroundColor White
    Write-Host "  IP: $targetIP" -ForegroundColor Gray
    Write-Host "  Hostname: $targetHostname" -ForegroundColor Gray
    Write-Host "  External MAC: $externalMac" -ForegroundColor Gray
    Write-Host "  Internal MAC: $internalMac" -ForegroundColor Gray
    Write-Host "  Status: $(if ($configured) { 'Success' } else { 'Failed' })" -ForegroundColor $(if ($configured) { 'Green' } else { 'Red' })
    Write-Host ""

    if ($configured) {
        Write-Log "IMPORTANT: VM may require reboot for hostname changes to take effect" -Level Warning
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
