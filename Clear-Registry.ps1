<#
.SYNOPSIS
    Clears all VMM registry data

.DESCRIPTION
    Completely removes all VMM registry entries including:
    - All VM instance records
    - Global settings (template paths, defaults, etc.)

    This does NOT affect:
    - Hyper-V VMs (they remain intact)
    - VHD files
    - Template files

    After clearing, VMs can be re-imported using Import-VM.ps1

.EXAMPLE
    .\Clear-Registry.ps1
    Prompts for confirmation before clearing

.EXAMPLE
    .\Clear-Registry.ps1 -Force
    Clears without confirmation
#>

[CmdletBinding()]
param(
    [switch]$Force
)

# Load shared functions
. "$PSScriptRoot\Common.ps1"

#region Main

try {
    Write-ScriptHeader -Title "Clear VMM Registry Data"
    Test-AdministratorPrivileges

    # Check if registry exists
    if (-not (Test-Path $script:RegistryBasePath)) {
        Write-Host "No VMM registry data found." -ForegroundColor Yellow
        exit 0
    }

    # Get current stats
    $vmCount = 0
    if (Test-Path $script:RegistryInstancesPath) {
        $vmCount = (Get-ChildItem -Path $script:RegistryInstancesPath -ErrorAction SilentlyContinue | Measure-Object).Count
    }

    # Show what will be deleted
    Write-Host "This will remove:" -ForegroundColor White
    Write-Host "  - $vmCount VM instance record(s)" -ForegroundColor Gray
    Write-Host "  - Global settings (template paths, defaults)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "This will NOT affect:" -ForegroundColor White
    Write-Host "  - Hyper-V VMs (they remain intact)" -ForegroundColor Gray
    Write-Host "  - VHD files" -ForegroundColor Gray
    Write-Host "  - Template files" -ForegroundColor Gray
    Write-Host ""

    # Confirm unless forced
    if (-not $Force) {
        if (-not (Request-UserConfirmation -Message "Clear all registry data?" -CancelMessage "Cancelled")) {
            exit 0
        }
    }

    # Remove the entire registry key
    Write-Host ""
    Write-Log "Removing registry data..." -Level Warning
    Remove-Item -Path $script:RegistryBasePath -Recurse -Force -ErrorAction Stop
    Write-Log "Registry data cleared successfully" -Level Success

    Write-Host ""
    Write-Host "Done. Use Import-VM.ps1 to re-import existing VMs." -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Log "ERROR: $($_.Exception.Message)" -Level Error
    Write-Host ""
    exit 1
}

#endregion
