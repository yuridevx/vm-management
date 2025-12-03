#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Shows status of all managed VMs and system information.

.DESCRIPTION
    Displays:
    - All VMs in registry with their current status
    - Hyper-V VM status (running, stopped, etc.)
    - Network configuration
    - GPU assignments
    - Sync status between registry and Hyper-V

.PARAMETER VMName
    Show status for specific VM only. If not specified, shows all VMs.

.PARAMETER Detailed
    Show detailed information including MAC addresses and paths.

.EXAMPLE
    .\Status.ps1
    Shows summary of all managed VMs

.EXAMPLE
    .\Status.ps1 -Detailed
    Shows detailed information for all VMs

.EXAMPLE
    .\Status.ps1 -VMName "MyVM"
    Shows status for specific VM
#>

[CmdletBinding()]
param(
    [string]$VMName = "",
    [switch]$Detailed
)

# Load shared functions
. "$PSScriptRoot\Common.ps1"

#region Main Execution

try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  VMM Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Get global settings
    $globalSettings = Get-GlobalSettingsFromRegistry

    if ($globalSettings) {
        Write-Host "Global Settings:" -ForegroundColor Yellow
        Write-Host "  Registry Version: $($globalSettings.Version)" -ForegroundColor Gray
        if ($globalSettings.TemplateVHDX) {
            $templateExists = Test-Path $globalSettings.TemplateVHDX
            Write-Host "  Template VHDX: $($globalSettings.TemplateVHDX)" -ForegroundColor $(if ($templateExists) { 'Gray' } else { 'Red' })
            if (-not $templateExists) {
                Write-Host "    (FILE NOT FOUND)" -ForegroundColor Red
            }
        }
        if ($globalSettings.VHDFolder) {
            Write-Host "  VHD Folder: $($globalSettings.VHDFolder)" -ForegroundColor Gray
        }
        Write-Host ""
    }

    # Get all VMs from registry
    $registryVMs = Get-AllVMInstancesFromRegistry

    # Get all Hyper-V VMs
    $hyperVVMs = Get-VM -ErrorAction SilentlyContinue

    # Filter if specific VM requested
    if (-not [string]::IsNullOrWhiteSpace($VMName)) {
        $registryVMs = @($registryVMs | Where-Object { $_.Name -eq $VMName })
        if ($registryVMs.Count -eq 0) {
            Write-Host "VM '$VMName' not found in registry" -ForegroundColor Yellow
            Write-Host ""

            # Check if it exists in Hyper-V
            $hvVM = $hyperVVMs | Where-Object { $_.Name -eq $VMName }
            if ($hvVM) {
                Write-Host "VM exists in Hyper-V but not managed. Use Import-VM.ps1 to import it." -ForegroundColor Gray
            }
            exit 0
        }
    }

    # Ensure registryVMs is an array for consistent .Count behavior
    $registryVMs = @($registryVMs)

    # Show VM table
    Write-Host "Managed VMs ($($registryVMs.Count)):" -ForegroundColor Yellow
    Write-Host ""

    if ($registryVMs.Count -eq 0) {
        Write-Host "  No VMs in registry. Use Deploy-VM.ps1 or Import-VM.ps1 to add VMs." -ForegroundColor Gray
        Write-Host ""
    }
    else {
        # Table header
        Write-Host "  Name                State      IP            GPU                    Configured" -ForegroundColor White
        Write-Host "  ----                -----      --            ---                    ----------" -ForegroundColor DarkGray

        foreach ($vm in $registryVMs) {
            # Get current Hyper-V state
            $hvVM = $hyperVVMs | Where-Object { $_.VMId.Guid -eq $vm.ID }
            $state = "NOT FOUND"
            $stateColor = "Red"

            if ($hvVM) {
                $state = $hvVM.State.ToString()

                # Check if name changed
                if ($hvVM.Name -ne $vm.Name) {
                    Sync-VMNameInRegistry -VMID $vm.ID -NewName $hvVM.Name | Out-Null
                    $vm.Name = $hvVM.Name
                }

                $stateColor = switch ($state) {
                    "Running" { "Green" }
                    "Off" { "Gray" }
                    "Saved" { "Yellow" }
                    "Paused" { "Yellow" }
                    default { "White" }
                }
            }

            $name = $vm.Name.PadRight(18).Substring(0, 18)
            $statePad = $state.PadRight(10).Substring(0, 10)
            $ipValue = if ($vm.InternalIP) { $vm.InternalIP } else { "N/A" }
            $ip = $ipValue.PadRight(13).Substring(0, 13)
            $gpu = if ($vm.GPUName) { $vm.GPUName } else { "N/A" }
            if ($gpu.Length -gt 22) { $gpu = $gpu.Substring(0, 19) + "..." }
            $gpu = $gpu.PadRight(22)
            $configured = if ($vm.Configured) { "Yes" } else { "No" }

            Write-Host "  $name " -NoNewline -ForegroundColor White
            Write-Host "$statePad " -NoNewline -ForegroundColor $stateColor
            Write-Host "$ip " -NoNewline -ForegroundColor Cyan

            Write-Host "$gpu " -NoNewline -ForegroundColor Magenta
            Write-Host "$configured" -ForegroundColor $(if ($vm.Configured) { 'Green' } else { 'Yellow' })

            if ($Detailed) {
                Write-Host "    ID: $($vm.ID)" -ForegroundColor DarkGray
                Write-Host "    VHD: $($vm.VHDPath)" -ForegroundColor DarkGray
                Write-Host "    Memory: $([Math]::Round($vm.Memory / 1MB, 0)) MB, CPUs: $($vm.CPU)" -ForegroundColor DarkGray
                Write-Host ""
            }
        }

        Write-Host ""
    }

    # Show unmanaged VMs
    $unmanagedVMs = @()
    foreach ($hvVM in $hyperVVMs) {
        $isManaged = $registryVMs | Where-Object { $_.ID -eq $hvVM.VMId.Guid }
        if (-not $isManaged) {
            $unmanagedVMs += $hvVM
        }
    }

    if ($unmanagedVMs.Count -gt 0) {
        Write-Host "Unmanaged Hyper-V VMs ($($unmanagedVMs.Count)):" -ForegroundColor Yellow
        foreach ($vm in $unmanagedVMs) {
            Write-Host "  - $($vm.Name) ($($vm.State))" -ForegroundColor Gray
        }
        Write-Host "  Use Import-VM.ps1 to manage these VMs" -ForegroundColor DarkGray
        Write-Host ""
    }

    # Show orphaned registry entries
    $orphanedEntries = @()
    foreach ($regVM in $registryVMs) {
        $hvVM = $hyperVVMs | Where-Object { $_.VMId.Guid -eq $regVM.ID }
        if (-not $hvVM) {
            $orphanedEntries += $regVM
        }
    }

    if ($orphanedEntries.Count -gt 0) {
        Write-Host "Orphaned Registry Entries ($($orphanedEntries.Count)):" -ForegroundColor Red
        foreach ($vm in $orphanedEntries) {
            Write-Host "  - $($vm.Name) (ID: $($vm.ID))" -ForegroundColor Gray
        }
        Write-Host "  Use Clean.ps1 to remove orphaned entries" -ForegroundColor DarkGray
        Write-Host ""
    }

    # Show GPUs
    Write-Host "Available GPUs:" -ForegroundColor Yellow
    $gpus = Get-AllAvailableGPUs
    if ($gpus.Count -eq 0) {
        Write-Host "  No GPUs detected" -ForegroundColor Gray
    }
    else {
        foreach ($gpu in $gpus) {
            Write-Host "  - $($gpu.FriendlyName)" -ForegroundColor Magenta
        }
    }
    Write-Host ""

}
catch {
    Write-Host ""
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    exit 1
}

#endregion
