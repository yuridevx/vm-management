#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    View and configure default settings for VM deployment.

.DESCRIPTION
    Displays current default values stored in registry and allows users to
    interactively update them. Settings include VHD folder, template path,
    default memory, and default CPU count.

.PARAMETER Show
    Only display current settings without prompting for changes.

.EXAMPLE
    .\Defaults.ps1
    Shows current defaults and prompts to change them.

.EXAMPLE
    .\Defaults.ps1 -Show
    Only displays current defaults without prompting.
#>

[CmdletBinding()]
param(
    [switch]$Show
)

# Load shared functions
. "$PSScriptRoot\Common.ps1"

function Format-Bytes {
    param([int64]$Bytes)
    if ($Bytes -ge 1GB) { return "$([Math]::Round($Bytes / 1GB, 1)) GB" }
    if ($Bytes -ge 1MB) { return "$([Math]::Round($Bytes / 1MB, 0)) MB" }
    return "$Bytes bytes"
}

function Show-CurrentDefaults {
    param([hashtable]$Settings)

    Write-Host ""
    Write-Host "Current Default Settings:" -ForegroundColor Cyan
    Write-Host "─────────────────────────────────────────" -ForegroundColor DarkGray

    if ($null -eq $Settings) {
        Write-Host "  (No settings configured yet)" -ForegroundColor Yellow
        return
    }

    $vhdFolder = if ($Settings.VHDFolder) { $Settings.VHDFolder } else { "(not set)" }
    $templateVHDX = if ($Settings.TemplateVHDX) { $Settings.TemplateVHDX } else { "(not set)" }
    $memory = if ($Settings.DefaultMemory) { Format-Bytes $Settings.DefaultMemory } else { "(not set)" }
    $cpu = if ($Settings.DefaultCPU) { $Settings.DefaultCPU } else { "(not set)" }

    Write-Host "  VHD Folder:     " -NoNewline -ForegroundColor White
    Write-Host $vhdFolder -ForegroundColor Gray
    Write-Host "  Template VHDX:  " -NoNewline -ForegroundColor White
    Write-Host $templateVHDX -ForegroundColor Gray
    Write-Host "  Default Memory: " -NoNewline -ForegroundColor White
    Write-Host $memory -ForegroundColor Gray
    Write-Host "  Default CPU:    " -NoNewline -ForegroundColor White
    Write-Host $cpu -ForegroundColor Gray

    if ($Settings.Updated) {
        Write-Host ""
        Write-Host "  Last Updated:   " -NoNewline -ForegroundColor DarkGray
        Write-Host $Settings.Updated -ForegroundColor DarkGray
    }

    Write-Host "─────────────────────────────────────────" -ForegroundColor DarkGray
}

function Read-ValidatedInput {
    param(
        [string]$Prompt,
        [string]$CurrentValue,
        [string]$ValidationPattern,
        [string]$ValidationMessage,
        [switch]$IsPath,
        [switch]$IsMemory,
        [switch]$IsNumber,
        [int]$MinValue,
        [int]$MaxValue
    )

    $displayCurrent = if ($CurrentValue) { $CurrentValue } else { "(none)" }
    Write-Host ""
    Write-Host "$Prompt" -ForegroundColor Yellow
    Write-Host "  Current: $displayCurrent" -ForegroundColor DarkGray
    Write-Host "  (Press Enter to keep current value)" -ForegroundColor DarkGray
    $userInput = Read-Host "  New value"

    if ([string]::IsNullOrWhiteSpace($userInput)) {
        return $CurrentValue
    }

    if ($IsPath) {
        # Expand environment variables
        $userInput = [Environment]::ExpandEnvironmentVariables($userInput)
    }

    if ($IsMemory) {
        # Parse memory string like "8GB", "4096MB", etc.
        if ($userInput -match '^(\d+)\s*(GB|MB|KB)?$') {
            $value = [int64]$Matches[1]
            $unit = if ($Matches[2]) { $Matches[2].ToUpper() } else { "MB" }

            switch ($unit) {
                "GB" { $userInput = $value * 1GB }
                "MB" { $userInput = $value * 1MB }
                "KB" { $userInput = $value * 1KB }
                default { $userInput = $value * 1MB }
            }
        }
        else {
            Write-Host "  Invalid memory format. Use format like: 8GB, 4096MB" -ForegroundColor Red
            return $CurrentValue
        }
    }

    if ($IsNumber) {
        if ($userInput -notmatch '^\d+$') {
            Write-Host "  Invalid number." -ForegroundColor Red
            return $CurrentValue
        }
        $userInput = [int]$userInput
        if ($MinValue -and $userInput -lt $MinValue) {
            Write-Host "  Value must be at least $MinValue." -ForegroundColor Red
            return $CurrentValue
        }
        if ($MaxValue -and $userInput -gt $MaxValue) {
            Write-Host "  Value must be at most $MaxValue." -ForegroundColor Red
            return $CurrentValue
        }
    }

    if ($ValidationPattern -and $userInput -notmatch $ValidationPattern) {
        Write-Host "  $ValidationMessage" -ForegroundColor Red
        return $CurrentValue
    }

    return $userInput
}

function Prompt-ForDefaults {
    param([hashtable]$CurrentSettings)

    if ($null -eq $CurrentSettings) {
        $CurrentSettings = @{}
    }

    Write-Host ""
    Write-Host "Configure Default Settings" -ForegroundColor Cyan
    Write-Host "(Leave blank to keep current value)" -ForegroundColor DarkGray

    # VHD Folder
    $vhdFolder = Read-ValidatedInput `
        -Prompt "VHD Folder (where VM disks are stored):" `
        -CurrentValue $CurrentSettings.VHDFolder `
        -IsPath

    # Template VHDX
    $templateVHDX = Read-ValidatedInput `
        -Prompt "Template VHDX path (GPU-enabled template):" `
        -CurrentValue $CurrentSettings.TemplateVHDX `
        -IsPath

    # Default Memory
    $currentMemoryStr = if ($CurrentSettings.DefaultMemory) {
        Format-Bytes $CurrentSettings.DefaultMemory
    } else { $null }

    Write-Host ""
    Write-Host "Default Memory (e.g., 8GB, 4096MB):" -ForegroundColor Yellow
    Write-Host "  Current: $(if ($currentMemoryStr) { $currentMemoryStr } else { '(none)' })" -ForegroundColor DarkGray
    Write-Host "  (Press Enter to keep current value)" -ForegroundColor DarkGray
    $memoryInput = Read-Host "  New value"

    $defaultMemory = $CurrentSettings.DefaultMemory
    if (-not [string]::IsNullOrWhiteSpace($memoryInput)) {
        if ($memoryInput -match '^(\d+)\s*(GB|MB)?$') {
            $value = [int64]$Matches[1]
            $unit = if ($Matches[2]) { $Matches[2].ToUpper() } else { "MB" }

            switch ($unit) {
                "GB" { $defaultMemory = $value * 1GB }
                "MB" { $defaultMemory = $value * 1MB }
                default { $defaultMemory = $value * 1MB }
            }
        }
        else {
            Write-Host "  Invalid format, keeping current value." -ForegroundColor Red
        }
    }

    # Default CPU
    $defaultCPU = Read-ValidatedInput `
        -Prompt "Default CPU count:" `
        -CurrentValue $CurrentSettings.DefaultCPU `
        -IsNumber `
        -MinValue 1 `
        -MaxValue 64

    return @{
        VHDFolder = $vhdFolder
        TemplateVHDX = $templateVHDX
        DefaultMemory = $defaultMemory
        DefaultCPU = $defaultCPU
    }
}

#region Main Execution

try {
    Write-ScriptHeader -Title "VMM Default Settings"

    # Get current settings
    $currentSettings = Get-GlobalSettingsFromRegistry

    # Show current settings
    Show-CurrentDefaults -Settings $currentSettings

    if ($Show) {
        exit 0
    }

    # Prompt for changes
    Write-Host ""
    $modify = Read-Host "Modify settings? (Y/N)"

    if ($modify -notmatch '^[Yy]') {
        Write-Host ""
        Write-Host "No changes made." -ForegroundColor Gray
        exit 0
    }

    $newSettings = Prompt-ForDefaults -CurrentSettings $currentSettings

    # Show summary of changes
    Write-Host ""
    Write-Host "New Settings:" -ForegroundColor Cyan
    Write-Host "─────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  VHD Folder:     $($newSettings.VHDFolder)" -ForegroundColor White
    Write-Host "  Template VHDX:  $($newSettings.TemplateVHDX)" -ForegroundColor White
    Write-Host "  Default Memory: $(Format-Bytes $newSettings.DefaultMemory)" -ForegroundColor White
    Write-Host "  Default CPU:    $($newSettings.DefaultCPU)" -ForegroundColor White
    Write-Host "─────────────────────────────────────────" -ForegroundColor DarkGray

    Write-Host ""
    $confirm = Read-Host "Save these settings? (Y/N)"

    if ($confirm -notmatch '^[Yy]') {
        Write-Host ""
        Write-Host "Changes discarded." -ForegroundColor Yellow
        exit 0
    }

    # Save to registry
    Save-GlobalSettingsToRegistry -Settings $newSettings

    Write-Host ""
    Write-Host "Settings saved successfully." -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Log "ERROR: $($_.Exception.Message)" -Level Error
    exit 1
}

#endregion
