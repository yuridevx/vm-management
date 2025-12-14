#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Deploys a single Hyper-V VM with GPU driver injection and network configuration.

.DESCRIPTION
    Creates exactly 1 Hyper-V VM with:
    - Uses existing template VHDX with GPU drivers (create via Update-GPU.ps1)
    - Dual network setup (External + Internal)
    - Random MAC addresses (TP-Link OUI)
    - Random hostname assignment
    - Static IP configuration
    - GPU partition adapter assignment
    - Registry-based state tracking

.PARAMETER VMName
    Name for the VM. Default: HyperV-VM

.PARAMETER Memory
    Amount of memory per VM in bytes. Default: 5200MB (non-dynamic)

.PARAMETER CPU
    Number of virtual CPUs (reserved/committed). Default: 4

.PARAMETER VHDFolder
    Folder to store VM VHD files. Default: C:\VMs

.PARAMETER InternalIP
    Static IP for internal network. Default: auto-assigned from 10.0.0.10+

.PARAMETER VMUsername
    Username for VM login via PowerShell Direct. Default: home

.PARAMETER VMPassword
    Password for VM login via PowerShell Direct. Default: home

.PARAMETER GPUName
    GPU name to use for driver injection and partition assignment. Default: AUTO (first available)

.PARAMETER EmptyVHD
    Create an empty VHD instead of using a source VHDX. Will prompt for size.

.PARAMETER VHDSizeGB
    Size of empty VHD in GB. Only used with -EmptyVHD. Default: prompts user

.PARAMETER LogFile
    Path to log file. If not specified, creates timestamped log in VHD folder.

.EXAMPLE
    .\Deploy-VM.ps1
    Creates 1 VM with default settings using template VHDX

.EXAMPLE
    .\Deploy-VM.ps1 -VMName "MyVM" -Memory 8GB -CPU 8
    Creates 1 VM with custom resources

.EXAMPLE
    .\Deploy-VM.ps1 -VMName "BlankVM" -EmptyVHD -VHDSizeGB 100
    Creates 1 VM with a blank 100GB VHD (for manual OS installation)
#>

[CmdletBinding()]
param(
    [string]$VMName = "HyperV-VM",
    [int64]$Memory = 5200MB,
    [int]$CPU = 4,
    [string]$VHDFolder = "C:\VMs",
    [string]$InternalIP = "",
    [string]$VMUsername = "home",
    [string]$VMPassword = "home",
    [string]$GPUName = "AUTO",
    [switch]$EmptyVHD,
    [int]$VHDSizeGB = 0,
    [string]$LogFile = ""
)

# Load shared functions
. "$PSScriptRoot\Common.ps1"

# Apply defaults from constants if parameters not explicitly provided
if (-not $PSBoundParameters.ContainsKey('VMName')) {
    $VMName = $script:DEFAULT_VM_NAME
}
if (-not $PSBoundParameters.ContainsKey('Memory')) {
    $Memory = $script:DEFAULT_MEMORY
}
if (-not $PSBoundParameters.ContainsKey('CPU')) {
    $CPU = $script:DEFAULT_CPU
}
if (-not $PSBoundParameters.ContainsKey('VHDFolder')) {
    $VHDFolder = $script:DEFAULT_VHD_FOLDER
}
if (-not $PSBoundParameters.ContainsKey('VMUsername')) {
    $VMUsername = $script:DEFAULT_VM_USERNAME
}
if (-not $PSBoundParameters.ContainsKey('VMPassword')) {
    $VMPassword = $script:DEFAULT_VM_PASSWORD
}
if (-not $PSBoundParameters.ContainsKey('GPUName')) {
    $GPUName = $script:DEFAULT_GPU_NAME
}

# Override with registry settings if available
$globalSettings = Get-GlobalSettingsFromRegistry
if ($globalSettings) {
    if (-not $PSBoundParameters.ContainsKey('Memory') -and $globalSettings.DefaultMemory) {
        $Memory = [int64]$globalSettings.DefaultMemory
    }
    if (-not $PSBoundParameters.ContainsKey('CPU') -and $globalSettings.DefaultCPU) {
        $CPU = [int]$globalSettings.DefaultCPU
    }
    if (-not $PSBoundParameters.ContainsKey('VHDFolder') -and $globalSettings.VHDFolder) {
        $VHDFolder = $globalSettings.VHDFolder
    }
}

#region Helper Functions

function Test-InputValidation {
    param([int64]$Memory, [int]$CPU, [string]$VHDFolder)

    $errors = @()

    # Validate Memory
    $memoryMB = $Memory / 1MB
    if ($memoryMB -lt $script:MIN_MEMORY_MB) { $errors += "Insufficient memory (minimum $script:MIN_MEMORY_MB MB)" }
    if ($memoryMB -gt $script:MAX_MEMORY_MB) { $errors += "Memory too high (maximum $script:MAX_MEMORY_MB MB)" }

    # Validate CPU
    if ($CPU -lt $script:MIN_CPU) { $errors += "CPU count must be at least $script:MIN_CPU" }
    if ($CPU -gt $script:MAX_CPU) { $errors += "CPU count exceeds maximum ($script:MAX_CPU)" }

    # Validate VHD folder path
    $parentPath = Split-Path $VHDFolder -Parent
    if ($parentPath -and -not (Test-Path $parentPath)) {
        $errors += "Parent folder does not exist: $parentPath"
    }

    if ($errors.Count -gt 0) {
        foreach ($err in $errors) {
            Write-Log $err -Level Error
        }
        throw "Input validation failed"
    }

    Write-Log "Input validation passed" -Level Success
}

function Test-Prerequisites {
    Write-Log "Checking prerequisites..." -Level Info

    # Check if running as Administrator
    Test-AdministratorPrivileges

    # Check Hyper-V service
    $vmms = Get-Service -Name vmms -ErrorAction SilentlyContinue
    if (-not $vmms) {
        throw "Hyper-V Virtual Machine Management service (vmms) not found. Is Hyper-V installed?"
    }
    if ($vmms.Status -ne 'Running') {
        Write-Log "Starting Hyper-V service..." -Level Warning
        Start-Service -Name vmms
        Start-Sleep -Seconds 3
    }
    Write-Log "Hyper-V service: Running"

    # Check Hyper-V module
    if (-not (Get-Module -Name Hyper-V -ListAvailable)) {
        throw "Hyper-V PowerShell module not found."
    }
    Write-Log "Hyper-V PowerShell module: OK"

    Write-Log "All prerequisites met" -Level Success
}

function Initialize-NetworkSwitches {
    # External Switch
    if (-not (Get-VMSwitch -Name $script:ExternalSwitch -ErrorAction SilentlyContinue)) {
        $adapters = @(Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and !$_.Virtual })
        if ($adapters.Count -eq 0) { throw "No physical adapters found for external switch" }

        if ($adapters.Count -eq 1) {
            Write-Log "Auto-selecting only available adapter: $($adapters[0].Name)"
            $sel = 0
        } else {
            Write-Host "`nSelect physical adapter for external switch:"
            for ($i = 0; $i -lt $adapters.Count; $i++) {
                Write-Host "  $($i+1). $($adapters[$i].Name) - $($adapters[$i].InterfaceDescription)"
            }
            do { $sel = [int](Read-Host "Select adapter (1-$($adapters.Count))") - 1 }
            while ($sel -lt 0 -or $sel -ge $adapters.Count)
        }

        New-VMSwitch -Name $script:ExternalSwitch -NetAdapterName $adapters[$sel].Name -AllowManagementOS $true | Out-Null
        Write-Log "Created external switch on $($adapters[$sel].Name)" -Level Success
    } else {
        Write-Log "External switch already exists" -Level Success
    }

    # Internal Switch
    if (-not (Get-VMSwitch -Name $script:InternalSwitch -ErrorAction SilentlyContinue)) {
        New-VMSwitch -Name $script:InternalSwitch -SwitchType Internal | Out-Null
        Write-Log "Created internal switch" -Level Success
    } else {
        Write-Log "Internal switch already exists" -Level Success
    }

    # Configure Host IP
    Start-Sleep -Seconds 2
    $adapter = Get-NetAdapter | Where-Object { $_.Name -like "*$script:InternalSwitch*" }
    if (-not $adapter) { throw "Cannot find internal switch adapter" }

    if (-not (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -eq $script:HostIP })) {
        Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
        New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $script:HostIP -PrefixLength 24 | Out-Null
        Write-Log "Configured host IP: $script:HostIP/24" -Level Success
    } else {
        Write-Log "Host IP already configured: $script:HostIP" -Level Success
    }
}

# Get-TemplateVHDXPath, New-VMFromEmptyVHD and Get-NextAvailableIP are in Common.ps1

#endregion

#region Main Execution

try {
    Write-ScriptHeader -Title "Hyper-V Single VM Deployment"

    # Check prerequisites
    Test-Prerequisites
    Write-Host ""

    $LogFile = Initialize-Script -LogFile $LogFile -DefaultLogFolder $VHDFolder

    # Setup VHD folder
    if (-not (Test-Path $VHDFolder)) {
        Write-Log "Creating VHD folder: $VHDFolder"
        New-Item -Path $VHDFolder -ItemType Directory -Force | Out-Null
    }

    # Check if VM already exists
    $existingVM = Get-VMInstanceFromRegistry -VMName $VMName
    if ($existingVM) {
        Write-Log "VM '$VMName' already exists in registry" -Level Warning
        Write-Host ""
        Write-Host "Options:" -ForegroundColor Yellow
        Write-Host "  1. Exit (keep existing VM)"
        Write-Host "  2. Recreate VM (delete and create new)"
        Write-Host ""
        $choice = Read-Host "Select option (1-2)"

        if ($choice -eq "2") {
            Write-Log "Removing existing VM..." -Level Warning
            Remove-VMCompletely -VMName $VMName -VHDPath $existingVM.VHDPath -IncludeVHD | Out-Null
            Remove-VMInstanceFromRegistry -VMName $VMName | Out-Null
        } else {
            Write-Log "Keeping existing VM. Exiting." -Level Info
            exit 0
        }
    }

    # Also check Hyper-V directly
    if (Test-VMExists -VMName $VMName) {
        Write-Log "VM '$VMName' exists in Hyper-V but not in registry. Removing..." -Level Warning
        Remove-VMCompletely -VMName $VMName -IncludeVHD | Out-Null
    }

    # Validate inputs
    Test-InputValidation -Memory $Memory -CPU $CPU -VHDFolder $VHDFolder

    # Detect GPUs
    $availableGPUs = @(Show-AvailableGPUs)

    # Handle empty VHD or template VHDX
    $useEmptyVHD = $EmptyVHD
    $templateVHDX = $null
    $vhdSizeBytes = 0

    if ($useEmptyVHD) {
        Write-Host ""
        Write-Log "Creating VM with empty VHD (for manual OS installation)" -Level Info

        # Get VHD size
        if ($VHDSizeGB -le 0) {
            Write-Host ""
            Write-Host "Enter VHD size in GB (e.g., 100 for 100GB): " -NoNewline -ForegroundColor Cyan
            $sizeInput = Read-Host
            $VHDSizeGB = [int]$sizeInput
        }

        if ($VHDSizeGB -lt $script:MIN_VHD_SIZE_GB) {
            throw "VHD size must be at least $script:MIN_VHD_SIZE_GB GB"
        }
        if ($VHDSizeGB -gt $script:MAX_VHD_SIZE_GB) {
            throw "VHD size cannot exceed $script:MAX_VHD_SIZE_GB GB ($([int]($script:MAX_VHD_SIZE_GB / 1024))TB)"
        }

        $vhdSizeBytes = [int64]$VHDSizeGB * 1GB
        Write-Log "VHD Size: $VHDSizeGB GB" -Level Success
    }
    else {
        # Get template VHDX (must already exist)
        Write-Host ""
        $templateVHDX = Get-TemplateVHDXPath -VHDFolder $VHDFolder

        if (-not $templateVHDX) {
            $expectedPath = Get-ExpectedTemplatePath -VHDFolder $VHDFolder
            Write-Log "Template VHDX not found: $expectedPath" -Level Warning
            Write-Host ""
            Write-Host "Do you want to create an empty VHD? (Y/N): " -NoNewline -ForegroundColor Cyan
            $confirm = Read-Host

            if ($confirm -match '^[Yy]') {
                $useEmptyVHD = $true
                Write-Host "Size (GB): " -NoNewline -ForegroundColor Cyan
                $VHDSizeGB = [int](Read-Host)

                if ($VHDSizeGB -lt $script:MIN_VHD_SIZE_GB) {
                    throw "VHD size must be at least $script:MIN_VHD_SIZE_GB GB"
                }
                if ($VHDSizeGB -gt $script:MAX_VHD_SIZE_GB) {
                    throw "VHD size cannot exceed $script:MAX_VHD_SIZE_GB GB ($([int]($script:MAX_VHD_SIZE_GB / 1024))TB)"
                }

                $vhdSizeBytes = [int64]$VHDSizeGB * 1GB
                Write-Log "VHD Size: $VHDSizeGB GB (Fixed)" -Level Success
            } else {
                Write-Log "Exiting. Run Update-GPU.ps1 to create a template VHDX." -Level Info
                exit 0
            }
        }
    }

    # Setup network
    Write-Log "Setting up network infrastructure..."
    Initialize-NetworkSwitches

    # Determine IP address
    if ([string]::IsNullOrWhiteSpace($InternalIP)) {
        $InternalIP = Get-NextAvailableIP
    }

    # Generate hostname
    $hostname = Get-RandomHostname

    # VM paths
    $vhdPath = Join-Path $VHDFolder "$VMName.vhdx"

    # Show deployment summary
    Write-Host ""
    Write-Host "Deploying: $VMName (Memory: $($Memory / 1MB)MB, CPUs: $CPU, IP: $InternalIP)" -ForegroundColor Yellow
    if ($useEmptyVHD) {
        Write-Host "VHD Type: Empty ($VHDSizeGB GB) - OS installation required" -ForegroundColor Yellow
    }
    Write-Host ""

    # Select GPU
    $assignedGPU = Select-GPUForVM -VMName $VMName -AvailableGPUs $availableGPUs -AssignedGPU $null

    # Create VM (from template or empty)
    Write-Host ""
    Write-Log "Creating VM: $VMName" -Level Info

    if ($useEmptyVHD) {
        # Create VM with empty VHD
        $vmResult = New-VMFromEmptyVHD -VMName $VMName `
                                       -VHDPath $vhdPath `
                                       -VHDSizeBytes $vhdSizeBytes `
                                       -MemoryBytes $Memory `
                                       -ProcessorCount $CPU `
                                       -GPUInstancePath $assignedGPU

        Write-Log "  External MAC: $($vmResult.ExternalMAC)"
        Write-Log "  Internal MAC: $($vmResult.InternalMAC)"

        # For empty VHD, we can't configure network (no OS yet)
        $configured = $false
        Write-Log "Skipping network configuration (empty VHD - no OS installed)" -Level Warning
    }
    else {
        # Create VM from template
        $vmResult = New-VMFromTemplate -VMName $VMName `
                                       -TemplateVHDX $templateVHDX `
                                       -VHDPath $vhdPath `
                                       -MemoryBytes $Memory `
                                       -ProcessorCount $CPU `
                                       -GPUInstancePath $assignedGPU

        Write-Log "  External MAC: $($vmResult.ExternalMAC)"
        Write-Log "  Internal MAC: $($vmResult.InternalMAC)"

        # Create credentials
        $VMCredential = New-VMCredential -Username $VMUsername -Password $VMPassword

        # Configure network
        Write-Log "Starting VM for configuration..."
        $vmStarted = Start-VMSafely -VMName $VMName
        $configured = $false

        if ($vmStarted) {
            $heartbeatReady = Wait-VMHeartbeat -VMName $VMName -TimeoutSeconds $script:VM_HEARTBEAT_TIMEOUT_SEC

            if ($heartbeatReady) {
                $configured = Configure-VMNetwork -VMName $VMName `
                                                 -InternalIP $InternalIP `
                                                 -Hostname $hostname `
                                                 -Credential $VMCredential `
                                                 -InternalMAC $vmResult.InternalMAC `
                                                 -MaxRetries $script:MAX_CONFIG_RETRIES
            }
        }

        # Stop VM after configuration
        Write-Log "Shutting down VM after configuration..."
        Stop-VMSafely -VMName $VMName -WaitForShutdown | Out-Null
    }

    # Get GPU friendly name
    $gpuFriendlyName = ($availableGPUs | Where-Object { $_.InstancePath -eq $assignedGPU }).FriendlyName

    # Save to registry - only store what can't be inferred from VM state
    $vmGuid = $vmResult.VM.VMId.Guid
    $vmData = @{
        InternalIP = $InternalIP
        Configured = $configured
    }

    Save-VMInstanceToRegistry -VMID $vmGuid -VMData $vmData

    # Save global settings
    Save-GlobalSettingsToRegistry -Settings @{
        TemplateVHDX = $templateVHDX
        VHDFolder = $VHDFolder
        DefaultMemory = $Memory
        DefaultCPU = $CPU
    }

    # Summary
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  Deployment Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Log "VM Details:" -Level Info
    Write-Host "  Name: $VMName" -ForegroundColor White
    Write-Host "  ID: $($vmResult.VM.VMId.Guid)" -ForegroundColor Gray
    Write-Host "  Internal IP: $InternalIP" -ForegroundColor Gray
    Write-Host "  External MAC: $($vmResult.ExternalMAC)" -ForegroundColor Gray
    Write-Host "  Internal MAC: $($vmResult.InternalMAC)" -ForegroundColor Gray
    Write-Host "  GPU: $gpuFriendlyName" -ForegroundColor Cyan
    Write-Host "  Configured: $(if ($configured) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($configured) { 'Green' } else { 'Yellow' })
    Write-Host ""
    Write-Log "Network Configuration:" -Level Info
    Write-Host "  External Switch: $script:ExternalSwitch (Internet via DHCP)" -ForegroundColor Gray
    Write-Host "  Internal Switch: $script:InternalSwitch (Host-only 10.0.0.0/24)" -ForegroundColor Gray
    Write-Host "  Host IP: $script:HostIP" -ForegroundColor Gray
    Write-Host ""
    Write-Log "State stored in registry: $script:RegistryInstancesPath\$VMName" -Level Info
    Write-Host ""
    Write-Log "IMPORTANT: VM may require reboot for hostname changes to take effect." -Level Warning
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Log "CRITICAL ERROR: $($_.Exception.Message)" -Level Error
    Write-Log "Stack trace: $($_.ScriptStackTrace)" -Level Error
    Write-Host ""

    # Cleanup on failure
    if ($VMName -and (Test-VMExists -VMName $VMName)) {
        Write-Host "Clean up partially created VM? (Y/N): " -NoNewline
        $cleanup = Read-Host
        if ($cleanup -match '^[Yy]') {
            Remove-VMCompletely -VMName $VMName -IncludeVHD | Out-Null
            Remove-VMInstanceFromRegistry -VMName $VMName | Out-Null
            Write-Log "Cleanup completed" -Level Success
        }
    }

    exit 1
}

#endregion
