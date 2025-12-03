#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules Hyper-V

<#
.SYNOPSIS
    Deploys a single Hyper-V VM with GPU driver injection and network configuration.

.DESCRIPTION
    Creates exactly 1 Hyper-V VM with:
    - GPU driver injection into VHD (original VHDX is NEVER modified)
    - Creates a template VHDX with GPU drivers, then clones it for the VM
    - Dual network setup (External + Internal)
    - Random MAC addresses (TP-Link OUI)
    - Random hostname assignment
    - Static IP configuration
    - GPU partition adapter assignment
    - Registry-based state tracking

.PARAMETER VHDXPath
    Path to source VHDX file. If empty, searches for *.vhdx in current folder.

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
    Creates 1 VM with default settings using source VHDX

.EXAMPLE
    .\Deploy-VM.ps1 -VHDXPath "C:\Images\Win11.vhdx" -VMName "MyVM" -Memory 8GB -CPU 8
    Creates 1 VM with custom resources from source VHDX

.EXAMPLE
    .\Deploy-VM.ps1 -VMName "BlankVM" -EmptyVHD -VHDSizeGB 100
    Creates 1 VM with a blank 100GB VHD (for manual OS installation)
#>

[CmdletBinding()]
param(
    [string]$VHDXPath = "",
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

# Resource limits
$MIN_MEMORY_MB = 512
$MAX_MEMORY_MB = 131072
$MIN_CPU = 1
$MAX_CPU = 64

# Timeouts and retries
$VM_HEARTBEAT_TIMEOUT_SEC = 90
$MAX_CONFIG_RETRIES = 3

#region Helper Functions

function Test-InputValidation {
    param([int64]$Memory, [int]$CPU, [string]$VHDFolder)

    $errors = @()

    # Validate Memory
    $memoryMB = $Memory / 1MB
    if ($memoryMB -lt $MIN_MEMORY_MB) { $errors += "Insufficient memory (minimum $MIN_MEMORY_MB MB)" }
    if ($memoryMB -gt $MAX_MEMORY_MB) { $errors += "Memory too high (maximum $MAX_MEMORY_MB MB)" }

    # Validate CPU
    if ($CPU -lt $MIN_CPU) { $errors += "CPU count must be at least $MIN_CPU" }
    if ($CPU -gt $MAX_CPU) { $errors += "CPU count exceeds maximum ($MAX_CPU)" }

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

function Find-SourceVHDX {
    if (-not [string]::IsNullOrWhiteSpace($VHDXPath)) {
        if (Test-Path $VHDXPath) { return (Resolve-Path $VHDXPath).Path }
        throw "Specified VHDX not found: $VHDXPath"
    }

    $vhdxFiles = Get-ChildItem -Path . -Filter "*.vhdx" -File
    if ($vhdxFiles.Count -eq 0) { throw "No VHDX files found. Specify -VHDXPath" }
    if ($vhdxFiles.Count -eq 1) {
        Write-Log "Found VHDX: $($vhdxFiles[0].Name)" -Level Success
        return $vhdxFiles[0].FullName
    }

    Write-Host "`nSelect VHDX file:"
    for ($i = 0; $i -lt $vhdxFiles.Count; $i++) {
        Write-Host "  $($i+1). $($vhdxFiles[$i].Name) ($([Math]::Round($vhdxFiles[$i].Length/1GB, 2)) GB)"
    }
    do { $sel = [int](Read-Host "Select (1-$($vhdxFiles.Count))") - 1 }
    while ($sel -lt 0 -or $sel -ge $vhdxFiles.Count)
    return $vhdxFiles[$sel].FullName
}

function Initialize-TemplateVHDX {
    param(
        [string]$VHDFolder,
        [array]$AvailableGPUs,
        [string]$SourceVHDX
    )

    $templateVHDX = Join-Path $VHDFolder "template-with-gpu.vhdx"

    if (-not (Test-Path $templateVHDX)) {
        Write-Host ""
        Write-Log "Creating GPU-enabled template (this may take several minutes)..." -Level Info
        Copy-Item -Path $SourceVHDX -Destination $templateVHDX -Force -ErrorAction Stop

        if (-not (Test-Path $templateVHDX)) {
            throw "Template copy failed - file not created"
        }

        Inject-GpuDrivers -VHDPath $templateVHDX -GPUList $AvailableGPUs
        Write-Log "Template VHDX created successfully" -Level Success
    }
    else {
        Write-Log "Using existing template: $templateVHDX" -Level Success
    }

    return $templateVHDX
}

function New-EmptyVHDX {
    <#
    .SYNOPSIS
        Creates an empty VHDX file for VM creation
    #>
    param(
        [string]$VHDPath,
        [int64]$SizeBytes
    )

    Write-Log "Creating empty VHDX: $VHDPath ($([Math]::Round($SizeBytes/1GB, 2)) GB)" -Level Info

    # Create dynamic VHDX
    New-VHD -Path $VHDPath -SizeBytes $SizeBytes -Dynamic | Out-Null

    if (-not (Test-Path $VHDPath)) {
        throw "Failed to create empty VHDX"
    }

    Write-Log "Empty VHDX created successfully" -Level Success
    return $VHDPath
}

function New-VMFromEmptyVHD {
    <#
    .SYNOPSIS
        Creates a new VM with an empty VHD (no template, no GPU driver injection)
    #>
    param(
        [string]$VMName,
        [string]$VHDPath,
        [int64]$VHDSizeBytes,
        [int64]$MemoryBytes,
        [int]$ProcessorCount,
        [string]$GPUInstancePath
    )

    # Create empty VHD
    New-EmptyVHDX -VHDPath $VHDPath -SizeBytes $VHDSizeBytes

    # Create VM
    Write-Log "Creating VM: $VMName"
    $vm = New-VM -Name $VMName -MemoryStartupBytes $MemoryBytes -VHDPath $VHDPath `
                 -Generation 2 -ErrorAction Stop

    # Configure VM settings
    Set-VM -Name $VMName -ProcessorCount $ProcessorCount -StaticMemory `
           -CheckpointType Disabled -GuestControlledCacheTypes $true `
           -LowMemoryMappedIoSpace 3GB -HighMemoryMappedIoSpace 33GB -ErrorAction Stop
    Get-VMNetworkAdapter -VMName $VMName | Remove-VMNetworkAdapter

    # Add network adapters with unique random TP-Link MACs
    foreach ($switchName in @($script:ExternalSwitch, $script:InternalSwitch)) {
        Add-VMNetworkAdapter -VMName $VMName -SwitchName $switchName -Name $switchName
        $mac = Set-VMStaticMac -VMName $VMName -SwitchName $switchName -Force
        Write-Log "$switchName adapter MAC: $mac"
    }

    # Add GPU partition adapter with specific GPU assignment (ensure only 1 GPU)
    Get-VMGpuPartitionAdapter -VMName $VMName -ErrorAction SilentlyContinue | Remove-VMGpuPartitionAdapter -ErrorAction SilentlyContinue
    if (-not [string]::IsNullOrWhiteSpace($GPUInstancePath)) {
        Add-VMGpuPartitionAdapter -VMName $VMName -InstancePath $GPUInstancePath -ErrorAction Stop
        Write-Log "VM '$VMName' created with GPU: $GPUInstancePath" -Level Success
    } else {
        Add-VMGpuPartitionAdapter -VMName $VMName -ErrorAction Stop
        Write-Log "VM '$VMName' created with GPU partition adapter (no specific GPU assigned)" -Level Warning
    }

    # Get assigned MAC addresses
    $adapters = Get-VMNetworkAdapter -VMName $VMName
    $externalMac = ($adapters | Where-Object { $_.Name -eq $script:ExternalSwitch }).MacAddress
    $internalMac = ($adapters | Where-Object { $_.Name -eq $script:InternalSwitch }).MacAddress

    return @{
        VM = $vm
        ExternalMAC = $externalMac
        InternalMAC = $internalMac
    }
}

# Get-NextAvailableIP is now in Common.ps1

#endregion

#region Main Execution

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Hyper-V Single VM Deployment" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    # Check prerequisites
    Test-Prerequisites
    Write-Host ""

    # Initialize log file
    $LogFile = Initialize-LogFile -LogFile $LogFile -DefaultFolder $VHDFolder
    Write-Log "Logging to file: $LogFile"
    Write-Host ""

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
    Write-Log "Detecting available GPUs..."
    $availableGPUs = Get-AllAvailableGPUs
    Write-Log "Found $($availableGPUs.Count) GPU(s):" -Level Success
    foreach ($gpu in $availableGPUs) {
        Write-Log "  - $($gpu.FriendlyName)"
    }

    # Handle empty VHD or source VHDX
    $useEmptyVHD = $EmptyVHD
    $sourceVHDX = $null
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

        if ($VHDSizeGB -lt 10) {
            throw "VHD size must be at least 10 GB"
        }
        if ($VHDSizeGB -gt 2048) {
            throw "VHD size cannot exceed 2048 GB (2TB)"
        }

        $vhdSizeBytes = [int64]$VHDSizeGB * 1GB
        Write-Log "VHD Size: $VHDSizeGB GB" -Level Success
    }
    else {
        # Find source VHDX
        Write-Host ""
        $sourceVHDX = Find-SourceVHDX
        Write-Log "Source VHDX: $sourceVHDX" -Level Success

        # Create template if needed
        $templateVHDX = Initialize-TemplateVHDX -VHDFolder $VHDFolder -AvailableGPUs $availableGPUs -SourceVHDX $sourceVHDX
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

    # Show deployment plan
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  Deployment Plan" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "VM Name: $VMName" -ForegroundColor White
    Write-Host "Memory: $($Memory / 1MB) MB" -ForegroundColor Gray
    Write-Host "CPUs: $CPU" -ForegroundColor Gray
    Write-Host "Internal IP: $InternalIP" -ForegroundColor Gray
    Write-Host "Hostname: $hostname" -ForegroundColor Gray
    Write-Host "VHD Path: $vhdPath" -ForegroundColor Gray
    if ($useEmptyVHD) {
        Write-Host "VHD Type: Empty ($VHDSizeGB GB)" -ForegroundColor Yellow
        Write-Host "NOTE: You will need to install an OS manually" -ForegroundColor Yellow
    } else {
        Write-Host "VHD Type: From template" -ForegroundColor Gray
    }
    Write-Host ""

    $confirm = Read-Host "Continue with deployment? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Log "Deployment cancelled by user" -Level Warning
        exit 0
    }

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
            $heartbeatReady = Wait-VMHeartbeat -VMName $VMName -TimeoutSeconds $VM_HEARTBEAT_TIMEOUT_SEC

            if ($heartbeatReady) {
                $configured = Configure-VMNetwork -VMName $VMName `
                                                 -InternalIP $InternalIP `
                                                 -Hostname $hostname `
                                                 -Credential $VMCredential `
                                                 -InternalMAC $vmResult.InternalMAC `
                                                 -MaxRetries $MAX_CONFIG_RETRIES
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
        SourceVHDX = $sourceVHDX
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
    Write-Host "  External Switch: External (Internet via DHCP)" -ForegroundColor Gray
    Write-Host "  Internal Switch: Internal (Host-only 10.0.0.0/24)" -ForegroundColor Gray
    Write-Host "  Host IP: 10.0.0.1" -ForegroundColor Gray
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
