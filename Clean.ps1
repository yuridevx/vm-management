#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Cleans up orphaned registry entries and optionally resets all VMM data.

.DESCRIPTION
    This script can:
    - Remove registry entries for VMs that no longer exist in Hyper-V
    - Remove all VMM registry data (full reset)
    - Verify and repair registry integrity

.PARAMETER OrphanedOnly
    Only remove orphaned entries (VMs in registry but not in Hyper-V).

.PARAMETER All
    Remove ALL VMM registry data (full reset). Requires confirmation.

.PARAMETER Force
    Skip confirmation prompts.

.PARAMETER LogFile
    Path to log file. If not specified, creates timestamped log.

.EXAMPLE
    .\Clean.ps1
    Interactive mode - shows what can be cleaned

.EXAMPLE
    .\Clean.ps1 -OrphanedOnly
    Removes only orphaned registry entries

.EXAMPLE
    .\Clean.ps1 -All -Force
    Removes all VMM registry data without confirmation
#>

[CmdletBinding()]
param(
    [switch]$OrphanedOnly,
    [switch]$All,
    [switch]$Force,
    [string]$LogFile = ""
)

# Load shared functions
. "$PSScriptRoot\Common.ps1"

#region Main Execution

try {
    Write-ScriptHeader -Title "VMM Registry Cleanup"
    $LogFile = Initialize-Script -LogFile $LogFile

    # Check if registry exists
    if (-not (Test-Path $script:RegistryBasePath)) {
        Write-Log "No VMM registry data found. Nothing to clean." -Level Info
        exit 0
    }

    # Get all registry VMs
    $registryVMs = Get-AllVMInstancesFromRegistry

    # Get all Hyper-V VMs
    $hyperVVMs = Get-VM -ErrorAction SilentlyContinue

    # Find orphaned entries (VMs in registry but not in Hyper-V)
    $orphanedEntries = Get-OrphanedVMInstances -RegistryVMs $registryVMs -HyperVVMs $hyperVVMs

    # Show current state
    Write-Host "Current State:" -ForegroundColor Yellow
    Write-Host "  VMs in registry: $($registryVMs.Count)" -ForegroundColor Gray
    Write-Host "  VMs in Hyper-V: $($hyperVVMs.Count)" -ForegroundColor Gray
    Write-Host "  Orphaned entries: $($orphanedEntries.Count)" -ForegroundColor $(if ($orphanedEntries.Count -gt 0) { 'Yellow' } else { 'Gray' })
    Write-Host ""

    if ($orphanedEntries.Count -gt 0) {
        Write-Host "Orphaned Entries:" -ForegroundColor Yellow
        foreach ($vm in $orphanedEntries) {
            $idDisplay = if ($vm.ID -and $vm.ID.Length -ge 8) { "$($vm.ID.Substring(0,8))..." } elseif ($vm.ID) { $vm.ID } else { "Unknown" }
            Write-Host "  - $($vm.Name) (ID: $idDisplay)" -ForegroundColor Gray
        }
        Write-Host ""
    }

    # Handle -All flag
    if ($All) {
        Write-Host "WARNING: This will remove ALL VMM registry data!" -ForegroundColor Red
        Write-Host "This includes:" -ForegroundColor Red
        Write-Host "  - All VM instance records" -ForegroundColor Gray
        Write-Host "  - Global settings (template path, etc.)" -ForegroundColor Gray
        Write-Host ""

        if (-not $Force) {
            $confirm = Read-Host "Type 'DELETE ALL' to confirm"
            if ($confirm -ne "DELETE ALL") {
                Write-Log "Cleanup cancelled by user" -Level Warning
                exit 0
            }
        }

        Write-Host ""
        Write-Log "Removing all VMM registry data..." -Level Warning

        try {
            Remove-Item -Path $script:RegistryBasePath -Recurse -Force -ErrorAction Stop
            Write-Log "All VMM registry data removed" -Level Success
        }
        catch {
            Write-Log "Failed to remove registry data: $($_.Exception.Message)" -Level Error
            exit 1
        }

        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "  Cleanup Complete" -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "All VMM registry data has been removed." -ForegroundColor Gray
        Write-Host "Run Deploy-VM.ps1 or Import-VM.ps1 to start fresh." -ForegroundColor Gray
        Write-Host ""
        exit 0
    }

    # Handle -OrphanedOnly or interactive mode
    if ($orphanedEntries.Count -eq 0) {
        Write-Log "No orphaned entries found. Registry is clean." -Level Success
        exit 0
    }

    if (-not $OrphanedOnly -and -not $Force) {
        if (-not (Request-UserConfirmation -Message "Remove $($orphanedEntries.Count) orphaned entries?" -CancelMessage "Cleanup cancelled by user")) {
            exit 0
        }
    }

    # Remove orphaned entries
    Write-Host ""
    Write-Log "Removing orphaned entries..." -Level Info

    $removedCount = 0
    $failedCount = 0

    foreach ($vm in $orphanedEntries) {
        Write-Host "  Removing: $($vm.Name)..." -NoNewline
        $success = Remove-VMInstanceFromRegistry -VMID $vm.ID
        if ($success) {
            Write-Host " OK" -ForegroundColor Green
            $removedCount++
        }
        else {
            Write-Host " FAILED" -ForegroundColor Red
            $failedCount++
        }
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Cleanup Complete" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Removed: $removedCount" -ForegroundColor Green
    if ($failedCount -gt 0) {
        Write-Host "  Failed: $failedCount" -ForegroundColor Red
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
