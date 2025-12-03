# .SYNOPSIS
#     UI version of AssignGPU.ps1 - Finds a specified GPU on the host and configures GPU partition settings for a VM with dialog interface
# .DESCRIPTION
#     Provides a Windows Forms dialog interface for selecting VM and GPU options instead of CLI parameters

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Get-GpuInfo {
    param(
        [string]$Name
    )
    if ($Name -eq 'AUTO') {
        $partitionable = Get-CimInstance -Namespace 'ROOT\virtualization\v2' -ClassName Msvm_PartitionableGpu |
                         Select-Object -First 1
        if (-not $partitionable) {
            throw "No partitionable GPU found on host."
        }
        $dev = Get-PnpDevice |
               Where-Object {
                   $_.DeviceID -Like "*$($partitionable.Name.Substring(8,16))*" -and
                   $_.Status   -eq 'OK'
               }
    }
    else {
        $dev = Get-PnpDevice |
               Where-Object {
                   $_.FriendlyName -eq $Name -and
                   $_.Status       -eq 'OK'
               }
    }

    if (-not $dev) {
        throw "No GPU found matching '$Name'."
    }

    [pscustomobject]@{
        FriendlyName = $dev.FriendlyName
        ServiceName  = $dev.Service
    }
}

function Show-VMGPUAssignDialog {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'VM GPU Partition Assignment'
    $form.Size = New-Object System.Drawing.Size(520,480)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false

    # VM Selection
    $lblVM = New-Object System.Windows.Forms.Label
    $lblVM.Location = New-Object System.Drawing.Point(20,20)
    $lblVM.Size = New-Object System.Drawing.Size(100,20)
    $lblVM.Text = 'Select VM:'
    $form.Controls.Add($lblVM)

    $cboVM = New-Object System.Windows.Forms.ComboBox
    $cboVM.Location = New-Object System.Drawing.Point(130,18)
    $cboVM.Size = New-Object System.Drawing.Size(350,20)
    $cboVM.DropDownStyle = 'DropDownList'
    
    # Get available VMs
    try {
        $vms = Get-VM | Select-Object -ExpandProperty Name | Sort-Object
        $cboVM.Items.AddRange($vms)
        if ($vms.Count -gt 0) { $cboVM.SelectedIndex = 0 }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to get VM list: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
    $form.Controls.Add($cboVM)

    # GPU Selection
    $lblGPU = New-Object System.Windows.Forms.Label
    $lblGPU.Location = New-Object System.Drawing.Point(20,60)
    $lblGPU.Size = New-Object System.Drawing.Size(100,20)
    $lblGPU.Text = 'Select GPU:'
    $form.Controls.Add($lblGPU)

    $cboGPU = New-Object System.Windows.Forms.ComboBox
    $cboGPU.Location = New-Object System.Drawing.Point(130,58)
    $cboGPU.Size = New-Object System.Drawing.Size(350,20)
    $cboGPU.DropDownStyle = 'DropDownList'
    
    # Get available GPUs
    try {
        $cboGPU.Items.Add('AUTO (First Available)')
        $gpus = Get-PnpDevice -Class Display | Where-Object Status -eq 'OK' | Select-Object -ExpandProperty FriendlyName | Sort-Object
        $cboGPU.Items.AddRange($gpus)
        $cboGPU.SelectedIndex = 0
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to get GPU list: $($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
    $form.Controls.Add($cboGPU)

    # Resource Allocation Section
    $grpResources = New-Object System.Windows.Forms.GroupBox
    $grpResources.Location = New-Object System.Drawing.Point(20,100)
    $grpResources.Size = New-Object System.Drawing.Size(460,210)
    $grpResources.Text = 'GPU Resource Allocation'
    $form.Controls.Add($grpResources)

    # VRAM Percentage
    $lblVRAM = New-Object System.Windows.Forms.Label
    $lblVRAM.Location = New-Object System.Drawing.Point(15,30)
    $lblVRAM.Size = New-Object System.Drawing.Size(120,20)
    $lblVRAM.Text = 'VRAM Allocation:'
    $grpResources.Controls.Add($lblVRAM)

    $trackVRAM = New-Object System.Windows.Forms.TrackBar
    $trackVRAM.Location = New-Object System.Drawing.Point(140,25)
    $trackVRAM.Size = New-Object System.Drawing.Size(230,45)
    $trackVRAM.Minimum = 10
    $trackVRAM.Maximum = 100
    $trackVRAM.Value = 50
    $trackVRAM.SmallChange = 5
    $trackVRAM.LargeChange = 5
    $trackVRAM.TickFrequency = 5
    $trackVRAM.TickStyle = 'BottomRight'
    $grpResources.Controls.Add($trackVRAM)

    $lblVRAMValue = New-Object System.Windows.Forms.Label
    $lblVRAMValue.Location = New-Object System.Drawing.Point(380,30)
    $lblVRAMValue.Size = New-Object System.Drawing.Size(60,20)
    $lblVRAMValue.Text = '50%'
    $grpResources.Controls.Add($lblVRAMValue)

    # Encode Percentage
    $lblEncode = New-Object System.Windows.Forms.Label
    $lblEncode.Location = New-Object System.Drawing.Point(15,75)
    $lblEncode.Size = New-Object System.Drawing.Size(120,20)
    $lblEncode.Text = 'Encode Capability:'
    $grpResources.Controls.Add($lblEncode)

    $trackEncode = New-Object System.Windows.Forms.TrackBar
    $trackEncode.Location = New-Object System.Drawing.Point(140,70)
    $trackEncode.Size = New-Object System.Drawing.Size(230,45)
    $trackEncode.Minimum = 10
    $trackEncode.Maximum = 100
    $trackEncode.Value = 50
    $trackEncode.SmallChange = 5
    $trackEncode.LargeChange = 5
    $trackEncode.TickFrequency = 5
    $trackEncode.TickStyle = 'BottomRight'
    $grpResources.Controls.Add($trackEncode)

    $lblEncodeValue = New-Object System.Windows.Forms.Label
    $lblEncodeValue.Location = New-Object System.Drawing.Point(380,75)
    $lblEncodeValue.Size = New-Object System.Drawing.Size(60,20)
    $lblEncodeValue.Text = '50%'
    $grpResources.Controls.Add($lblEncodeValue)

    # Decode Percentage
    $lblDecode = New-Object System.Windows.Forms.Label
    $lblDecode.Location = New-Object System.Drawing.Point(15,120)
    $lblDecode.Size = New-Object System.Drawing.Size(120,20)
    $lblDecode.Text = 'Decode Capability:'
    $grpResources.Controls.Add($lblDecode)

    $trackDecode = New-Object System.Windows.Forms.TrackBar
    $trackDecode.Location = New-Object System.Drawing.Point(140,115)
    $trackDecode.Size = New-Object System.Drawing.Size(230,45)
    $trackDecode.Minimum = 10
    $trackDecode.Maximum = 100
    $trackDecode.Value = 50
    $trackDecode.SmallChange = 5
    $trackDecode.LargeChange = 5
    $trackDecode.TickFrequency = 5
    $trackDecode.TickStyle = 'BottomRight'
    $grpResources.Controls.Add($trackDecode)

    $lblDecodeValue = New-Object System.Windows.Forms.Label
    $lblDecodeValue.Location = New-Object System.Drawing.Point(380,120)
    $lblDecodeValue.Size = New-Object System.Drawing.Size(60,20)
    $lblDecodeValue.Text = '50%'
    $grpResources.Controls.Add($lblDecodeValue)

    # Compute Percentage
    $lblCompute = New-Object System.Windows.Forms.Label
    $lblCompute.Location = New-Object System.Drawing.Point(15,165)
    $lblCompute.Size = New-Object System.Drawing.Size(120,20)
    $lblCompute.Text = 'Compute Power:'
    $grpResources.Controls.Add($lblCompute)

    $trackCompute = New-Object System.Windows.Forms.TrackBar
    $trackCompute.Location = New-Object System.Drawing.Point(140,160)
    $trackCompute.Size = New-Object System.Drawing.Size(230,45)
    $trackCompute.Minimum = 10
    $trackCompute.Maximum = 100
    $trackCompute.Value = 50
    $trackCompute.SmallChange = 5
    $trackCompute.LargeChange = 5
    $trackCompute.TickFrequency = 5
    $trackCompute.TickStyle = 'BottomRight'
    $grpResources.Controls.Add($trackCompute)

    $lblComputeValue = New-Object System.Windows.Forms.Label
    $lblComputeValue.Location = New-Object System.Drawing.Point(380,165)
    $lblComputeValue.Size = New-Object System.Drawing.Size(60,20)
    $lblComputeValue.Text = '50%'
    $grpResources.Controls.Add($lblComputeValue)

    # Update percentage labels when sliders change with 5% snap
    $trackVRAM.Add_ValueChanged({ 
        $snapped = [Math]::Round($trackVRAM.Value / 5.0) * 5
        if ($trackVRAM.Value -ne $snapped) { $trackVRAM.Value = $snapped }
        $lblVRAMValue.Text = "$($trackVRAM.Value)%" 
    })
    $trackEncode.Add_ValueChanged({ 
        $snapped = [Math]::Round($trackEncode.Value / 5.0) * 5
        if ($trackEncode.Value -ne $snapped) { $trackEncode.Value = $snapped }
        $lblEncodeValue.Text = "$($trackEncode.Value)%" 
    })
    $trackDecode.Add_ValueChanged({ 
        $snapped = [Math]::Round($trackDecode.Value / 5.0) * 5
        if ($trackDecode.Value -ne $snapped) { $trackDecode.Value = $snapped }
        $lblDecodeValue.Text = "$($trackDecode.Value)%" 
    })
    $trackCompute.Add_ValueChanged({ 
        $snapped = [Math]::Round($trackCompute.Value / 5.0) * 5
        if ($trackCompute.Value -ne $snapped) { $trackCompute.Value = $snapped }
        $lblComputeValue.Text = "$($trackCompute.Value)%" 
    })

    # Progress TextBox
    $lblProgress = New-Object System.Windows.Forms.Label
    $lblProgress.Location = New-Object System.Drawing.Point(20,320)
    $lblProgress.Size = New-Object System.Drawing.Size(100,20)
    $lblProgress.Text = 'Progress:'
    $form.Controls.Add($lblProgress)

    $txtProgress = New-Object System.Windows.Forms.TextBox
    $txtProgress.Location = New-Object System.Drawing.Point(20,345)
    $txtProgress.Size = New-Object System.Drawing.Size(460,60)
    $txtProgress.Multiline = $true
    $txtProgress.ScrollBars = 'Vertical'
    $txtProgress.ReadOnly = $true
    $form.Controls.Add($txtProgress)

    # Buttons
    $btnRun = New-Object System.Windows.Forms.Button
    $btnRun.Location = New-Object System.Drawing.Point(305,415)
    $btnRun.Size = New-Object System.Drawing.Size(85,25)
    $btnRun.Text = 'Run'
    $btnRun.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $btnRun
    $form.Controls.Add($btnRun)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Location = New-Object System.Drawing.Point(395,415)
    $btnCancel.Size = New-Object System.Drawing.Size(85,25)
    $btnCancel.Text = 'Cancel'
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $btnCancel
    $form.Controls.Add($btnCancel)

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $selectedVM = $cboVM.SelectedItem
        $selectedGPU = if ($cboGPU.SelectedIndex -eq 0) { 'AUTO' } else { $cboGPU.SelectedItem }

        if ([string]::IsNullOrWhiteSpace($selectedVM)) {
            [System.Windows.Forms.MessageBox]::Show("Please select a VM.", "Input Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return $null
        }

        return @{
            VMName = $selectedVM
            GPUName = $selectedGPU
            VRAMPercentage = $trackVRAM.Value
            EncodePercentage = $trackEncode.Value
            DecodePercentage = $trackDecode.Value
            ComputePercentage = $trackCompute.Value
        }
    }

    return $null
}

# Function to get available GPU resources
function Get-GPUAvailableResources {
    param($GPUName)
    
    # Try to get GPU memory info using WMI
    try {
        if ($GPUName -eq 'AUTO') {
            $gpu = Get-CimInstance -Namespace 'ROOT\virtualization\v2' -ClassName Msvm_PartitionableGpu | Select-Object -First 1
        } else {
            $gpu = Get-CimInstance -Namespace 'ROOT\virtualization\v2' -ClassName Msvm_PartitionableGpu | 
                   Where-Object { $_.Name -like "*$GPUName*" } | Select-Object -First 1
        }
        
        if ($gpu) {
            # Return the available partition sizes from the GPU
            return @{
                TotalVRAM = if ($gpu.TotalVRAM) { $gpu.TotalVRAM } else { 8GB }  # Default to 8GB if not available
                TotalEncode = if ($gpu.TotalEncode) { $gpu.TotalEncode } else { [uint64]::MaxValue }
                TotalDecode = if ($gpu.TotalDecode) { $gpu.TotalDecode } else { 8GB }
                TotalCompute = if ($gpu.TotalCompute) { $gpu.TotalCompute } else { 8GB }
            }
        }
    } catch {
        Write-Warning "Could not retrieve GPU resources automatically. Using defaults."
    }
    
    # Default values if we can't get actual GPU info
    return @{
        TotalVRAM = 8GB  # 8GB default VRAM
        TotalEncode = [uint64]::MaxValue
        TotalDecode = 8GB
        TotalCompute = 8GB
    }
}

# Main execution
$params = Show-VMGPUAssignDialog

if ($null -eq $params) {
    Write-Host "Operation cancelled by user."
    exit 0
}

$VMName = $params.VMName
$GPUName = $params.GPUName
$VRAMPercent = $params.VRAMPercentage
$EncodePercent = $params.EncodePercentage
$DecodePercent = $params.DecodePercentage
$ComputePercent = $params.ComputePercentage

$vm           = $null
$wasRunning   = $false

try {
    Write-Host "=== GPU Partition Assignment: VM '$VMName' ==="

    # Validate GPU existence by name
    Write-Host "Locating GPU '$GPUName' on the host..."
    $gpuInfo = Get-GpuInfo -Name $GPUName
    Write-Host "Using GPU: $($gpuInfo.FriendlyName) (Service: $($gpuInfo.ServiceName))"
    
    # Get available GPU resources
    Write-Host "Retrieving GPU resource information..."
    $gpuResources = Get-GPUAvailableResources -GPUName $GPUName
    
    # Calculate allocated resources based on percentages
    $vramAllocation = [uint64]($gpuResources.TotalVRAM * $VRAMPercent / 100)
    $encodeAllocation = [uint64]($gpuResources.TotalEncode * $EncodePercent / 100)
    $decodeAllocation = [uint64]($gpuResources.TotalDecode * $DecodePercent / 100)
    $computeAllocation = [uint64]($gpuResources.TotalCompute * $ComputePercent / 100)
    
    Write-Host "Resource Allocation:"
    Write-Host "  - VRAM: $($VRAMPercent)% = $([Math]::Round($vramAllocation/1MB, 2)) MB"
    Write-Host "  - Encode: $($EncodePercent)%"
    Write-Host "  - Decode: $($DecodePercent)% = $([Math]::Round($decodeAllocation/1MB, 2)) MB"
    Write-Host "  - Compute: $($ComputePercent)% = $([Math]::Round($computeAllocation/1MB, 2)) MB"

    # Retrieve the VM
    Write-Host "Retrieving VM '$VMName'..."
    $vm = Get-VM -Name $VMName -ErrorAction Stop

    # Determine running state and stop VM if necessary
    $wasRunning = $vm.State -eq 'Running'
    if ($wasRunning) {
        Write-Host "Stopping VM '$VMName'..."
        Stop-VM -Name $VMName -Force -ErrorAction Stop
        while ((Get-VM -Name $VMName).State -ne 'Off') {
            Write-Host "Waiting for VM to power off..."
            Start-Sleep -Seconds 2
        }
        Write-Host "VM is now Off."
    }

    # GPU partition adapter configuration
    Write-Host "Configuring GPU partition settings for VM '$VMName'..."
    $vmConfig = Get-VM -Name $VMName

    if (-not $vmConfig.GuestControlledCacheTypes) {
        Write-Host "Enabling GuestControlledCacheTypes..."
        Set-VM -GuestControlledCacheTypes $true -VMName $VMName -ErrorAction Stop
    }

    if ($vmConfig.LowMemoryMappedIoSpace -ne 1GB) {
        Write-Host "Setting LowMemoryMappedIoSpace to 1GB..."
        Set-VM -LowMemoryMappedIoSpace 1GB -VMName $VMName -ErrorAction Stop
    }

    if ($vmConfig.HighMemoryMappedIoSpace -ne 32GB) {
        Write-Host "Setting HighMemoryMappedIoSpace to 32GB..."
        Set-VM -HighMemoryMappedIoSpace 32GB -VMName $VMName -ErrorAction Stop
    }

    if (-not (Get-VMGpuPartitionAdapter -VMName $VMName -ErrorAction SilentlyContinue)) {
        Write-Host "Adding VM GPU Partition Adapter..."
        Add-VMGpuPartitionAdapter -VMName $VMName -ErrorAction Stop
    }

    $adapter = Get-VMGpuPartitionAdapter -VMName $VMName

    # Desired partition settings based on percentages
    $desired = @{
        MinPartitionVRAM        = $vramAllocation
        MaxPartitionVRAM        = $vramAllocation
        OptimalPartitionVRAM    = $vramAllocation
        MinPartitionEncode      = $encodeAllocation
        MaxPartitionEncode      = $encodeAllocation
        OptimalPartitionEncode  = $encodeAllocation
        MinPartitionDecode      = $decodeAllocation
        MaxPartitionDecode      = $decodeAllocation
        OptimalPartitionDecode  = $decodeAllocation
        MinPartitionCompute     = $computeAllocation
        MaxPartitionCompute     = $computeAllocation
        OptimalPartitionCompute = $computeAllocation
    }

    $needsUpdate = $false
    foreach ($key in $desired.Keys) {
        if ($adapter.$key -ne $desired[$key]) {
            $needsUpdate = $true
            break
        }
    }

    if ($needsUpdate) {
        Write-Host "Updating VM GPU Partition Adapter settings..."
        Set-VMGpuPartitionAdapter -VMName $VMName @desired -ErrorAction Stop
    }

    Write-Host "GPU partition assignment complete."
    
    $successMsg = @"
GPU partition assignment completed successfully for VM '$VMName'.

Resource Allocation:
- VRAM: $($VRAMPercent)% ($([Math]::Round($vramAllocation/1MB, 2)) MB)
- Encode: $($EncodePercent)%
- Decode: $($DecodePercent)% ($([Math]::Round($decodeAllocation/1MB, 2)) MB)
- Compute: $($ComputePercent)% ($([Math]::Round($computeAllocation/1MB, 2)) MB)
"@
    
    [System.Windows.Forms.MessageBox]::Show($successMsg, "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}
catch {
    $errorMsg = "ERROR: $($_.Exception.Message)`nScript stopped at line $($_.InvocationInfo.ScriptLineNumber)"
    Write-Error $errorMsg
    [System.Windows.Forms.MessageBox]::Show($errorMsg, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}
finally {
    if ($wasRunning) {
        try {
            Write-Host "Restarting VM '$VMName'..."
            Start-VM -Name $VMName -ErrorAction Stop
        }
        catch {
            Write-Warning "Warning: failed to restart VM: $($_.Exception.Message)"
        }
    }
    Write-Host "All done."
}