# .SYNOPSIS
#     UI version of MakeVM.ps1 - Injects GPU driver files into the largest partition of a VM's VHD with dialog interface
# .DESCRIPTION
#     Provides a Windows Forms dialog interface for selecting VM and GPU options instead of CLI parameters

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Get-GpuInfo {
    param($Name)
    if ($Name -eq 'AUTO') {
        $pg = Get-CimInstance -Namespace 'ROOT\virtualization\v2' -ClassName Msvm_PartitionableGpu |
              Select-Object -First 1
        if (-not $pg) {
            throw "No partitionable GPU found on host."
        }
        $dev = Get-PnpDevice |
               Where-Object {
                   $_.DeviceID -Like "*$($pg.Name.Substring(8,16))*" -and
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
        throw "No GPU found matching '$Name'"
    }
    [pscustomobject]@{
        FriendlyName = $dev.FriendlyName
        ServiceName  = $dev.Service
    }
}

function Copy-ServiceDriver {
    param($DriveRoot, $ServiceName)
    $svc = Get-CimInstance Win32_SystemDriver | Where-Object Name -eq $ServiceName
    if (-not $svc) {
        throw "Service driver '$ServiceName' not found on host."
    }
    $srcDir = Split-Path $svc.PathName -Parent
    $rel    = $srcDir.Substring('C:\Windows\System32\DriverStore'.Length)
    $dest   = Join-Path $DriveRoot "Windows\System32\HostDriverStore$rel"
    if (-not (Test-Path $dest)) {
        Write-Host "Copying service driver: $srcDir → $dest"
        Copy-Item $srcDir -Destination $dest -Recurse -ErrorAction Stop
    }
}

function Copy-SignedDrivers {
    param($DriveRoot, $GPUName, $Hostname)
    $mods = Get-CimInstance Win32_PnPSignedDriver | Where-Object DeviceName -eq $GPUName
    foreach ($mod in $mods) {
        $escaped = $mod.DeviceID -replace '\\','\\\\'
        $ante   = "\\$Hostname\ROOT\cimv2:Win32_PnPSignedDriver.DeviceID=`"$escaped`""
        $files  = Get-CimInstance Win32_PnPSignedDriverCIMDataFile |
                  Where-Object Antecedent -eq $ante

        foreach ($f in $files) {
            $path    = ($f.Dependent -split '=' | Select-Object -Last 1).Trim('"') -replace '\\\\','\\'
            if ($path -like 'C:\Windows\System32\DriverStore\*') {
                $rel  = $path.Substring('C:\Windows\System32\DriverStore'.Length)
                $dest = Join-Path $DriveRoot "Windows\System32\HostDriverStore$rel"
                if (-not (Test-Path $dest)) {
                    $srcDir = Split-Path $path -Parent
                    Write-Host "Copying DriverStore folder: $srcDir → $dest"
                    Copy-Item $srcDir -Destination $dest -Recurse -ErrorAction Stop
                }
            }
            else {
                $destDir = Split-Path ($path -replace 'C:',$DriveRoot) -Parent
                if (-not (Test-Path $destDir)) {
                    New-Item $destDir -ItemType Directory -Force | Out-Null
                }
                Write-Host "Copying file: $path → $destDir"
                Copy-Item $path -Destination $destDir -Force -ErrorAction Stop
            }
        }
    }
}

function Inject-GpuDrivers {
    param(
        [string]$DriveLetter,
        [string]$GpuName,
        [string]$HostName
    )
    $root = "$DriveLetter`:\"
    Write-Host "Preparing HostDriverStore under $root"
    New-Item (Join-Path $root 'Windows\System32\HostDriverStore') -ItemType Directory -Force | Out-Null

    $info = Get-GpuInfo -Name $GpuName
    Write-Host "Using GPU '$($info.FriendlyName)' (Service: $($info.ServiceName))"

    Copy-ServiceDriver -DriveRoot $root -ServiceName $info.ServiceName
    Copy-SignedDrivers  -DriveRoot $root -GPUName $info.FriendlyName -Hostname $HostName

    Write-Host "INFO: GPU driver injection complete for '$($info.FriendlyName)'."
}

function Show-VMGPUConfigDialog {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'VM GPU Driver Injection'
    $form.Size = New-Object System.Drawing.Size(500,350)
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
    $cboVM.Size = New-Object System.Drawing.Size(330,20)
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
    $cboGPU.Size = New-Object System.Drawing.Size(330,20)
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

    # Hostname
    $lblHost = New-Object System.Windows.Forms.Label
    $lblHost.Location = New-Object System.Drawing.Point(20,100)
    $lblHost.Size = New-Object System.Drawing.Size(100,20)
    $lblHost.Text = 'Hostname:'
    $form.Controls.Add($lblHost)

    $txtHost = New-Object System.Windows.Forms.TextBox
    $txtHost.Location = New-Object System.Drawing.Point(130,98)
    $txtHost.Size = New-Object System.Drawing.Size(330,20)
    $txtHost.Text = $env:COMPUTERNAME
    $form.Controls.Add($txtHost)

    # Progress TextBox
    $lblProgress = New-Object System.Windows.Forms.Label
    $lblProgress.Location = New-Object System.Drawing.Point(20,140)
    $lblProgress.Size = New-Object System.Drawing.Size(100,20)
    $lblProgress.Text = 'Progress:'
    $form.Controls.Add($lblProgress)

    $txtProgress = New-Object System.Windows.Forms.TextBox
    $txtProgress.Location = New-Object System.Drawing.Point(20,165)
    $txtProgress.Size = New-Object System.Drawing.Size(440,100)
    $txtProgress.Multiline = $true
    $txtProgress.ScrollBars = 'Vertical'
    $txtProgress.ReadOnly = $true
    $form.Controls.Add($txtProgress)

    # Buttons
    $btnRun = New-Object System.Windows.Forms.Button
    $btnRun.Location = New-Object System.Drawing.Point(285,275)
    $btnRun.Size = New-Object System.Drawing.Size(85,25)
    $btnRun.Text = 'Run'
    $btnRun.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $btnRun
    $form.Controls.Add($btnRun)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Location = New-Object System.Drawing.Point(375,275)
    $btnCancel.Size = New-Object System.Drawing.Size(85,25)
    $btnCancel.Text = 'Cancel'
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $btnCancel
    $form.Controls.Add($btnCancel)

    $result = $form.ShowDialog()

    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $selectedVM = $cboVM.SelectedItem
        $selectedGPU = if ($cboGPU.SelectedIndex -eq 0) { 'AUTO' } else { $cboGPU.SelectedItem }
        $hostname = $txtHost.Text

        if ([string]::IsNullOrWhiteSpace($selectedVM)) {
            [System.Windows.Forms.MessageBox]::Show("Please select a VM.", "Input Required", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return $null
        }

        return @{
            VMName = $selectedVM
            GPUName = $selectedGPU
            Hostname = if ([string]::IsNullOrWhiteSpace($hostname)) { $env:COMPUTERNAME } else { $hostname }
        }
    }

    return $null
}

# Main execution
$params = Show-VMGPUConfigDialog

if ($null -eq $params) {
    Write-Host "Operation cancelled by user."
    exit 0
}

$VMName = $params.VMName
$GPUName = $params.GPUName
$Hostname = $params.Hostname

$vm = $null; $vhd = $null; $disk = $null; $partition = $null; $driveLetter = $null; $wasRunning = $false

try {
    Write-Host "=== GPU Partition Driver Update: VM '$VMName' ==="
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

    # GPU initialization/configuration if not already applied
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
    $desired = @{ MinPartitionVRAM=160000000; MaxPartitionVRAM=160000000; OptimalPartitionVRAM=160000000;
                  MinPartitionEncode=2951479051793528320; MaxPartitionEncode=2951479051793528320; OptimalPartitionEncode=2951479051793528320;
                  MinPartitionDecode=160000000; MaxPartitionDecode=160000000; OptimalPartitionDecode=160000000;
                  MinPartitionCompute=160000000; MaxPartitionCompute=160000000; OptimalPartitionCompute=160000000 }
    $needsUpdate = $false
    foreach ($k in $desired.Keys) {
        if ($adapter.$k -ne $desired[$k]) { $needsUpdate = $true; break }
    }
    if ($needsUpdate) {
        Write-Host "Updating VM GPU Partition Adapter settings..."
        Set-VMGpuPartitionAdapter -VMName $VMName @desired -ErrorAction Stop
    }
    Write-Host "GPU partition initialization complete."

    Write-Host "Fetching VHD information..."
    $vhd = Get-VHD -VMId $vm.VMId -ErrorAction Stop
    Write-Host "Mounting VHD at '$($vhd.Path)'..."
    $disk = Mount-VHD -Path $vhd.Path -Passthru -ErrorAction Stop | Get-Disk -ErrorAction Stop

    Write-Host "Locating the largest partition on disk #$($disk.Number)..."
    $partition = Get-Partition -DiskNumber $disk.Number -ErrorAction Stop |
                 Sort-Object Size -Descending |
                 Select-Object -First 1
    if (-not $partition) { throw "No partitions found on disk $($disk.Number)" }
    Write-Host "Selected partition #$($partition.PartitionNumber) (~$([Math]::Round($partition.Size/1GB,2)) GB)."

    $available = ([char[]](68..90) | ForEach-Object {[string]$_}) |
                 Where-Object {$_ -notin (Get-PSDrive -PSProvider FileSystem).Name}
    $driveLetter = $available[0]
    Write-Host "Assigning drive letter '${driveLetter}:' to partition..."
    Set-Partition -DiskNumber $disk.Number `
                  -PartitionNumber $partition.PartitionNumber `
                  -NewDriveLetter $driveLetter -ErrorAction Stop

    Inject-GpuDrivers -DriveLetter $driveLetter -GpuName $GPUName -HostName $Hostname
    Write-Host "Driver injection completed successfully."
    [System.Windows.Forms.MessageBox]::Show("GPU driver injection completed successfully for VM '$VMName'.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}
catch {
    $errorMsg = "ERROR: $($_.Exception.Message)`nScript stopped at line $($_.InvocationInfo.ScriptLineNumber)"
    Write-Error $errorMsg
    [System.Windows.Forms.MessageBox]::Show($errorMsg, "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    exit 1
}
finally {
    Write-Host "=== Cleanup ==="
    if ($driveLetter) {
        try {
            Write-Host "Removing drive letter '${driveLetter}:'..."
            Remove-PartitionAccessPath -DiskNumber $disk.Number `
                                      -PartitionNumber $partition.PartitionNumber `
                                      -AccessPath "${driveLetter}:" -ErrorAction Stop
        }
        catch {
            Write-Warning "Warning: failed to remove drive letter: $($_.Exception.Message)"
        }
    }
    if ($vhd) {
        try {
            Write-Host "Dismounting VHD..."
            Dismount-VHD -Path $vhd.Path -ErrorAction Stop
        }
        catch {
            Write-Warning "Warning: failed to dismount VHD: $($_.Exception.Message)"
        }
    }
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