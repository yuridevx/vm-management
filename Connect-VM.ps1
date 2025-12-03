#requires -RunAsAdministrator
param(
    [string]$VMName = "HyperV-VM",
    [string]$Username = "home",
    [string]$Password = "home"
)

# Load shared functions
. "$PSScriptRoot\Common.ps1"

# Apply defaults from constants if not explicitly provided
if (-not $PSBoundParameters.ContainsKey('VMName')) {
    $VMName = $script:DEFAULT_VM_NAME
}
if (-not $PSBoundParameters.ContainsKey('Username')) {
    $Username = $script:DEFAULT_VM_USERNAME
}
if (-not $PSBoundParameters.ContainsKey('Password')) {
    $Password = $script:DEFAULT_VM_PASSWORD
}

$cred = New-VMCredential -Username $Username -Password $Password

Write-Host "Connecting to VM '$VMName' as '$Username'..." -ForegroundColor Cyan

# Test connection and run interactive session
try {
    # First test the connection
    $result = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
        @{
            ComputerName = $env:COMPUTERNAME
            Username = $env:USERNAME
            OS = (Get-CimInstance Win32_OperatingSystem).Caption
        }
    }

    Write-Host "Connected successfully!" -ForegroundColor Green
    Write-Host "  Computer: $($result.ComputerName)" -ForegroundColor White
    Write-Host "  User: $($result.Username)" -ForegroundColor White
    Write-Host "  OS: $($result.OS)" -ForegroundColor White

    # Return credential for further use
    return $cred
}
catch {
    Write-Host "Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    throw
}
