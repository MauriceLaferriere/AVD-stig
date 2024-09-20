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
    $subscriptionId
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

$regToken = (New-AzWvdRegistrationInfo -SubscriptionId $subscriptionId -ResourceGroupName $resourceGroupName -HostPoolName $hostPoolName -ExpirationTime (Get-Date).AddHours(2)).Token

# Download and install the AVD Agent
$agentInstaller = "C:\Temp\WVD-Agent.msi"
Invoke-WebRequest -Uri "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv" -OutFile $agentInstaller
Start-Process -FilePath 'msiexec.exe' -ArgumentList "/i $agentInstaller /quiet /norestart /passive REGISTRATIONTOKEN=$regToken" -Wait -PassThru
Start-Sleep -Seconds 5

# Download and install the AVD Agent Bootloader
$agentInstaller = "C:\Temp\WVD-Agent-Bootloader.msi"
Invoke-WebRequest -Uri "https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH" -OutFile $agentInstaller
Start-Process msiexec.exe -ArgumentList "/i $agentInstaller /quiet /norestart /passive" -Wait
Start-Sleep -Seconds 5


