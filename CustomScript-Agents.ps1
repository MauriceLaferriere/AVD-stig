Param(
    [parameter(Mandatory)]
    [string]
    $hostPoolName, 

    [parameter(Mandatory)]
    [string]
    $resourceGroupName,

    [parameter(Mandatory)]
    [string]
    $vmssName,
    
    [parameter(Mandatory)]
    [string]
    $subscriptionId,

    [parameter(Mandatory)]
    [string]
    $registrationToken
)

try {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force 
} catch {
    Write-Error "Failed to install NuGet: $_"
}

try {
    if (-not (Get-Module -ListAvailable -Name Az.DesktopVirtualization)) {
        Install-Module Az.DesktopVirtualization -Force
    }
} catch {
    Write-Error "Failed to install Az.DesktopVirtualization: $_"
}

try {
    if (-not (Get-Module -ListAvailable -Name Az)) {
        Install-Module Az -Force
    }
} catch {
    Write-Error "Failed to install RemoteDesktop: $_"
}

$folderPath = "C:\Temp"

if (-not (Test-Path -Path $folderPath)) {
    New-Item -Path $folderPath -ItemType Directory
}

#$registrationToken = (New-AzWvdRegistrationInfo -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -HostPoolName $hostPoolName -ExpirationTime (Get-Date).AddHours(2)).Token

#  Add Microsoft Entra ID Join Setting
$Setting = 
    # Enable PKU2U: https://docs.microsoft.com/en-us/azure/virtual-desktop/troubleshoot-azure-ad-connections#windows-desktop-client
    [PSCustomObject]@{
            Name         = 'AllowOnlineID'
            Path         = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u'
            PropertyType = 'DWord'
            Value        = 1
    }

# Create registry key if necessary
if (!(Test-Path -Path $Setting.Path)) {
    New-Item -Path $Setting.Path -Force
}

# Checks for existing registry setting
$Value = Get-ItemProperty -Path $Setting.Path -Name $Setting.Name -ErrorAction 'SilentlyContinue'

# Creates the registry setting when it does not exist
if (!$Value) {
    New-ItemProperty -Path $Setting.Path -Name $Setting.Name -PropertyType $Setting.PropertyType -Value $Setting.Value -Force
}
# Updates the registry setting when it already exists
elseif ($Value.$($Setting.Name) -ne $Setting.Value) {
    Set-ItemProperty -Path $Setting.Path -Name $Setting.Name -Value $Setting.Value -Force
}
Start-Sleep -Seconds 1

# Download and install the AVD Agent
$agentInstaller = "C:\Temp\WVD-Agent.msi"
Invoke-WebRequest -Uri "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv" -OutFile $agentInstaller
Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i $agentInstaller /quiet /norestart /passive REGISTRATIONTOKEN=$registrationToken" -Wait -PassThru
Start-Sleep -Seconds 5

# Download and install the AVD Agent Bootloader
$agentInstaller = "C:\Temp\WVD-Agent-Bootloader.msi"
Invoke-WebRequest -Uri "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH" -OutFile $agentInstaller
Start-Process msiexec.exe -ArgumentList "/i $agentInstaller /quiet /norestart /passive" -Wait
Start-Sleep -Seconds 5

# Restart the VM
Start-Process -FilePath 'shutdown' -ArgumentList '/r /t 30'

