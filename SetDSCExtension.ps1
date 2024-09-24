Param(
    [parameter(Mandatory)]
    [string]
    $vmName
)


Set-AzureVMDscExtension -VM $vmName `
    -ConfigurationArchive "https://raw.githubusercontent.com/MauriceLaferriere/AVD-stig/main/STIGWIN11.zip" `
    -ConfigurationName "ApplySTIGWIN11.ps1\STIGWIN11" `
    -ConfigurationArgument @{ }

