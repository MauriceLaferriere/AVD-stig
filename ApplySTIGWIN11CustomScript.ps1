try {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force 
} catch {
    Write-Error "Failed to install NuGet: $_"
}

try {
    Install-Module Az -Force
} catch {
    Write-Error "Failed to install Az module: $_"
}

try {
    Install-Module Az.DesktopVirtualization -Force
} catch {
    Write-Error "Failed to install Az.DesktopVirtualization: $_"
}

try {
    Install-Module -Name PowerSTIG -Force

    (Get-Module PowerStig -ListAvailable).RequiredModules | ForEach-Object {
        Install-Module -Name $_.Name -RequiredVersion $_.Version -Force
    }} catch {
    Write-Error "Failed to install required modules for PowerSTIG: $_"
}try {    Install-Module SecurityPolicyDsc -Force} catch {
    Write-Error "Failed to install SecurityPolicyDsc module: $_"
}
try {    Configuration STIGWIN11 {                    Import-Module -Name PowerSTIG        Node 'localhost' {            WindowsClient BaseLine {                OsVersion   = '11'	            SkipRule    = 'V-253495','V-253480','V-253282'                 Exception   = @{                    'V-253357' = @{                        ValueData = '1' # Required for using Azure Image Builder access to creation                    }                    'V-253491' = @{                        Identity = 'Guests'                     }                }            }        }    }    # Compile the configuration    STIGWIN11} catch {
    Write-Error "Failed to compile STIGWIN11 configuration: $_"
}

try {
    # Apply the configuration
    Start-DSCConfiguration -Path .\STIGWIN11 -Wait -Force -Verbose
} catch {
    Write-Error "Failed to apply STIGWIN11 configuration: $_"
}