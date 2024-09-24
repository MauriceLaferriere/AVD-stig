try {
    $folderPath = "C:\Temp"
    if (-not (Test-Path -Path $folderPath)) {
        New-Item -Path $folderPath -ItemType Directory
    }

    # Download the .mof file
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MauriceLaferriere/AVD-stig/main/STIGWIN11.mof" -OutFile "$folderPath\STIGWIN11.mof"

    # Apply the configuration
    Start-DSCConfiguration -Path $folderPath -Wait -Force -Verbose

} catch {
    Write-Error "Failed to apply STIGWIN11 configuration: $_"
}