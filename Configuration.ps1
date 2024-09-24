configuration AddSessionHost
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$HostPoolName,

        [Parameter(Mandatory = $false)]
        [string]$RegistrationInfoToken = "",

        [Parameter(Mandatory = $false)]
        [PSCredential]$RegistrationInfoTokenCredential = $null,

        [Parameter(Mandatory = $false)]
        [bool]$AadJoin = $false,

        [Parameter(Mandatory = $false)]
        [bool]$AadJoinPreview = $false,

        [Parameter(Mandatory = $false)]
        [string]$MdmId = "",

        [Parameter(Mandatory = $false)]
        [string]$SessionHostConfigurationLastUpdateTime = "",

        [Parameter(Mandatory = $false)]
        [bool]$EnableVerboseMsiLogging = $false,
        
        [Parameter(Mandatory = $false)]
        [bool]$UseAgentDownloadEndpoint = $false
    )

    $ErrorActionPreference = 'Stop'
    
    $ScriptPath = [system.io.path]::GetDirectoryName($PSCommandPath)
    . (Join-Path $ScriptPath "Functions.ps1")

    $rdshIsServer = isRdshServer

    Node localhost
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode = "ApplyOnly"
        }

        if ($rdshIsServer)
        {
            "$(get-date) - rdshIsServer = true: $rdshIsServer" | out-file c:\windows\temp\rdshIsServerResult.txt -Append
            WindowsFeature RDS-RD-Server
            {
                Ensure = "Present"
                Name = "RDS-RD-Server"
            }

            Script ExecuteRdAgentInstallServer
            {
                DependsOn = "[WindowsFeature]RDS-RD-Server"
                GetScript = {
                    return @{'Result' = ''}
                }
                SetScript = {
                    . (Join-Path $using:ScriptPath "Functions.ps1")
                    try {
                        & "$using:ScriptPath\Script-SetupSessionHost.ps1" -HostPoolName $using:HostPoolName -RegistrationInfoToken $using:RegistrationInfoToken -RegistrationInfoTokenCredential $using:RegistrationInfoTokenCredential -AadJoin $using:AadJoin -AadJoinPreview $using:AadJoinPreview -MdmId $using:MdmId -SessionHostConfigurationLastUpdateTime $using:SessionHostConfigurationLastUpdateTime -UseAgentDownloadEndpoint $using:UseAgentDownloadEndpoint -EnableVerboseMsiLogging:($using:EnableVerboseMsiLogging)
                    }
                    catch {
                        $ErrMsg = $PSItem | Format-List -Force | Out-String
                        Write-Log -Err $ErrMsg
                        throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallServer SetScript: $ErrMsg", $PSItem.Exception)
                    }
                }
                TestScript = {
                    . (Join-Path $using:ScriptPath "Functions.ps1")
                    
                    try {
                        return (& "$using:ScriptPath\Script-TestSetupSessionHost.ps1" -HostPoolName $using:HostPoolName)
                    }
                    catch {
                        $ErrMsg = $PSItem | Format-List -Force | Out-String
                        Write-Log -Err $ErrMsg
                        throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallServer TestScript: $ErrMsg", $PSItem.Exception)
                    }
                }
            }
        }
        else
        {
            "$(get-date) - rdshIsServer = false: $rdshIsServer" | out-file c:\windows\temp\rdshIsServerResult.txt -Append
            Script ExecuteRdAgentInstallClient
            {
                GetScript = {
                    return @{'Result' = ''}
                }
                SetScript = {
                    . (Join-Path $using:ScriptPath "Functions.ps1")
                    try {
                        & "$using:ScriptPath\Script-SetupSessionHost.ps1" -HostPoolName $using:HostPoolName -RegistrationInfoToken $using:RegistrationInfoToken -RegistrationInfoTokenCredential $using:RegistrationInfoTokenCredential -AadJoin $using:AadJoin -AadJoinPreview $using:AadJoinPreview -MdmId $using:MdmId -SessionHostConfigurationLastUpdateTime $using:SessionHostConfigurationLastUpdateTime -UseAgentDownloadEndpoint $using:UseAgentDownloadEndpoint -EnableVerboseMsiLogging:($using:EnableVerboseMsiLogging)
                    }
                    catch {
                        $ErrMsg = $PSItem | Format-List -Force | Out-String
                        Write-Log -Err $ErrMsg
                        throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallClient SetScript: $ErrMsg", $PSItem.Exception)
                    }
                }
                TestScript = {
                    . (Join-Path $using:ScriptPath "Functions.ps1")
                    
                    try {
                        return (& "$using:ScriptPath\Script-TestSetupSessionHost.ps1" -HostPoolName $using:HostPoolName)
                    }
                    catch {
                        $ErrMsg = $PSItem | Format-List -Force | Out-String
                        Write-Log -Err $ErrMsg
                        throw [System.Exception]::new("Some error occurred in DSC ExecuteRdAgentInstallClient TestScript: $ErrMsg", $PSItem.Exception)
                    }

                }
            }
        }
    }
}
# SIG # Begin signature block
# MIIoTgYJKoZIhvcNAQcCoIIoPzCCKDsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCQDVHUP8nRpbh7
# 7qUh2wf0Om2ZSMXyYaZaoiGTXdfZ/qCCDWowggY1MIIEHaADAgECAhMzAAAACWMn
# 7YqGMfm5AAAAAAAJMA0GCSqGSIb3DQEBDAUAMIGEMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS4wLAYDVQQDEyVXaW5kb3dzIEludGVybmFsIEJ1
# aWxkIFRvb2xzIFBDQSAyMDIwMB4XDTI0MDYxOTE4MTUzMVoXDTI1MDYxNzE4MTUz
# MVowgYQxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLjAsBgNV
# BAMTJVdpbmRvd3MgSW50ZXJuYWwgQnVpbGQgVG9vbHMgQ29kZVNpZ24wggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8hzd2IEs+Z6vJe1Ph36MjW51GBPHT
# ZZIYQRpyRgt+QuGPo4kbBnIiR1owrowXKYA4xiRiFq2nZOavdegFrxTAlFn1aCdQ
# 6ncidMVi4xUoY3AUyXAKXDL8wXDX1nmSpvT0HDm1c7QsIYCFNM4r7M6HaHA+k8JL
# jQyJN5piljfTiGTrnpJoBpbGMQluq8p11WX155BgWZ4EMAfh32nqO7HKXjZ6CFd2
# Cfn+8tfdQ/SCh9TxpJ8xM0gV+7bLI/2/bhvyBy2t5wN8nE0BvhDHqexqb2uOgcbG
# fR01Xf3wfPUhsP9P5gx6kEtbTOu/p+alng0SIGJbMh8IEikqTpE7vXKZAgMBAAGj
# ggGcMIIBmDAgBgNVHSUEGTAXBggrBgEFBQcDAwYLKwYBBAGCN0w3AQEwHQYDVR0O
# BBYEFHXvI7qCMN5A9CA67E5+euuA7osXMEUGA1UdEQQ+MDykOjA4MR4wHAYDVQQL
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFjAUBgNVBAUTDTQ1ODIwNCs1MDIzNjgw
# HwYDVR0jBBgwFoAUoH7qzmTrA0eRsqGw6GOA4/ZOZaEwaAYDVR0fBGEwXzBdoFug
# WYZXaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvV2luZG93cyUy
# MEludGVybmFsJTIwQnVpbGQlMjBUb29scyUyMFBDQSUyMDIwMjAuY3JsMHUGCCsG
# AQUFBwEBBGkwZzBlBggrBgEFBQcwAoZZaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jZXJ0cy9XaW5kb3dzJTIwSW50ZXJuYWwlMjBCdWlsZCUyMFRvb2xz
# JTIwUENBJTIwMjAyMC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQwFAAOC
# AgEAgQ1dOCwKwdC7GiZd++nSi3Zf0JFdql5djuONH/K1eYBkr8gmTJRcA+vCjNPa
# JdDOglcMjNb9v7TmfSfwoxq1MILay5t+W4QmlR+C7fIDTLZik/XSml+flbBiOjmk
# eEADJkhHpqU5aIxQZ89fa5fgrzyexW5XFSCCJSUOJCp/TujNu6m9RWG7ugsN2KPZ
# uF0aj5gUAmQQaUeRK7GZd9EHO9DKDUMl3ZbNAmcnKaV1jRQcrt4To6GGSLiCc1lp
# b5LrZnYdmiwGpLzBVGnrhK7z6vbyuhuUkO9HRwFWokeRGcwsCwXon/1woxsWWrR1
# V9b+1Wib/ZifdaprivedWI288rJyd5n7k0v+UYdj3HjoZUWovMnr7m5zmwHohJ/2
# P8uLU8aYIjb7olTDU5dbfopa2og6B+Ijq2Y1N0hc7uM+VY3wJcYp4bJF3gGxRmK2
# 1fDN592NWfjk2lKtB0tZ38LREVLcf4k7J3ENzjuamEgWkmECPvYtTuTdr+v4sgaA
# X37RdZB6zTsF2K5mXhlonscMNU4ThKCIM/aTfVAIaOPhSXwiHnEqZzqoFYYCl5k8
# LHY/JbUDfXROnAABXDVgDkSfPMpg0qYXDflrOO0I0ehKTg3g+D8X5C1La6+d3cuP
# 3C/DI/0zSVzaqawAATXWHcxlH/R8F2N/3Xn0sk4HlvoES28wggctMIIFFaADAgEC
# AhMzAAAAVlq1acsdlGgsAAAAAABWMA0GCSqGSIb3DQEBDAUAMH4xCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBT
# ZXJ2aWNlcyBQYXJ0bmVyIFJvb3QwHhcNMjAwMjA1MjIzNDEyWhcNMzUwMjA1MjI0
# NDEyWjCBhDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEuMCwG
# A1UEAxMlV2luZG93cyBJbnRlcm5hbCBCdWlsZCBUb29scyBQQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJeO8Bi8BZ0LmiWJmxhr8XqilrM9
# 8Le3i6/bgnolF1sE2w8obZr5HmO8FnkT+2TPpVMWsvnz8NaybPtns+i1a3lX+F85
# uM2pX+kBnaUPjRNZ4Nr4eYZeTNsu+fvJkkuFg1dcQqRypLdSbpSz4NSb6rjFxF7i
# Z2A7JnhVaR2eKSmFMCNH8fLz10ORthw/YwS1xvw/Lm5TU+YSRQWfydS+wgfMPapg
# oXtrOp28UH+HXoySBu0uQYC6azrB/eTPNiDQO4TlAJdWzV4yvLSpEKIVisUZTAQL
# cE9wVumQQvG8HKIF3v5hr+U/5aDEOJaqlNPqff99mYSuajKHQWPV4wJUHMohX93j
# nz7HhtJLhf/UeVglNcKayiiTI0NcCJbyPxD1/nCy2F3wnTmrF43lHJHHeNIunrNI
# sI6OhbELkWIZiVp83Dt9/5db2ULbdf564qRZAO2VUlvD0dFA1Ii9GZbqSThenYsY
# 0gnmZ1QIMJVJIt0zPUY1E0W+n/zkEedBM+jbaBw6De+zBNxTjpDg3qf1nRibmXGW
# SXv3uvyqzW+EnAozTUdr1LCCbsQTlEH+gzHG9nQy4zl1gTbbPMF77Lokxhueg/kr
# sHlsSGDI/GIBYu4fVvlU6uzAfahuQaFnIj5WHNkN6qwIFDFmNvpPRk+yOoMLAAm9
# XHKK1BxyOKixu/VTAgMBAAGjggGbMIIBlzAOBgNVHQ8BAf8EBAMCAYYwEAYJKwYB
# BAGCNxUBBAMCAQAwHQYDVR0OBBYEFKB+6s5k6wNHkbKhsOhjgOP2TmWhMFQGA1Ud
# IARNMEswSQYEVR0gADBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wGQYJKwYBBAGCNxQCBAwe
# CgBTAHUAYgBDAEEwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSNuOM2u9Xe
# l8uvDk17vlofCBv6BjBRBgNVHR8ESjBIMEagRKBChkBodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpb3BzL2NybC9NaWNTZXJQYXJSb290XzIwMTAtMDgtMjQuY3Js
# MF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNTZXJQYXJSb290XzIwMTAtMDgtMjQuY3J0
# MA0GCSqGSIb3DQEBDAUAA4ICAQBhSN9+w4ld9lyw3LwLhTlDV2sWMjpAjfOdbLFa
# tPpsSjVGHLBrfL+Y97dUfqCYNMYS5ByP41eRtKvrkby60pPxDjow8L/3tOVZmENd
# BU3vn28f7wCNy5gilO444fz4cBbUUQHnc94nMsODly3N6ohm5gGq7p0h9klLX/l5
# hbe2Rxl5UsJo3EuK8yqP7xz7thbL4QosQNsKiEFM91o8Q/Frdt+/gni6OTWVjCNM
# YHVB4CWttzJyvP8A1IzH0HEBG95Rdd9HMeudsYOHRuM4A0elUvRqOnsfqP7Zs46X
# NtBogW/IacvPGeuy3AHXIgMfFk35P9Mrt/ipDuqPy07faWLr0d+2++fWGv0yMSEf
# 0VWsMIYUK7fnmO+WK2j74KO/hFj3c+G/psecslWdT6zpeLntMB0IkqxN+Gw+qzc9
# 1vol2TEMHP2pITosnXYt33nZ9XR9YQmvMHBxwcF6qUALem5nOYMu574bCK6iOJdF
# SMfaUiLGppk7LOID0saA965KSWyxcpsxgvGnovjeUV1rJkN/NyPI3m5+t5w0v54J
# V2iCjgnsuF90m0cb2E3UUdEsbC6gBppQ/038OBoWMeVcd2ppmwP5O5vL5s4fCUp5
# p/og24gdqwrLJMZ+dHYVf3MsRqm7Lx3OVuxTuqbguRui+FdJtoBR/dMGFCWho1JE
# 8Qud9TGCGjowgho2AgEBMIGcMIGEMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMS4wLAYDVQQDEyVXaW5kb3dzIEludGVybmFsIEJ1aWxkIFRvb2xz
# IFBDQSAyMDIwAhMzAAAACWMn7YqGMfm5AAAAAAAJMA0GCWCGSAFlAwQCAQUAoIHU
# MBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgor
# BgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDVkCjGtCeYmgALnNw+izL7tFAPKeLx
# OVYvF25dJtdD1TBoBgorBgEEAYI3AgEMMVowWKA6gDgAVwBpAG4AZABvAHcAcwAg
# AEIAdQBpAGwAZAAgAFQAbwBvAGwAcwAgAEkAbgB0AGUAcgBuAGEAbKEagBhodHRw
# Oi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAF887lcv9z2GE
# Kv9L45OfnP5WQqGg/RWVL9XwFYmMRFwEIZQSQnmQd49vL5e/DA6AiOrX29maT/rI
# NFThypYVUcqSs3pmnQZ7oPmxb4CQDFrIAJeo9iUqx554lMATuMStTf8xVWNR/GxZ
# 3mdCxi2zGX0qrGftkoc4JpqUzCFPcmGJTg0wMgVCE9sGjez8WnA80e1hiQTob1n1
# vUEfAa5wwuyrpWTVoAF3EgQP0M0Djek0VJX/LgVoMdAiOPzoLrip2UvP3TdkiByp
# Qwj/Gc1bObuaucpxKyVeL5Ds2pfrxEuENsqF0Oo4FVgAARhk6Hb+Na9x4uJvrGfg
# TEPlraW656GCF5cwgheTBgorBgEEAYI3AwMBMYIXgzCCF38GCSqGSIb3DQEHAqCC
# F3AwghdsAgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFSBgsqhkiG9w0BCRABBKCCAUEE
# ggE9MIIBOQIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCNmIgF1nej
# 4xpDicd9PEkPjWSkXvdSGqtZaHs/MzwjUgIGZpVfNrFlGBMyMDI0MDgwNjEwMTIz
# NS43OTFaMASAAgH0oIHRpIHOMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25z
# MScwJQYDVQQLEx5uU2hpZWxkIFRTUyBFU046QTAwMC0wNUUwLUQ5NDcxJTAjBgNV
# BAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghHtMIIHIDCCBQigAwIB
# AgITMwAAAevgGGy1tu847QABAAAB6zANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMzEyMDYxODQ1MzRaFw0yNTAzMDUxODQ1
# MzRaMIHLMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYD
# VQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMScwJQYDVQQLEx5uU2hp
# ZWxkIFRTUyBFU046QTAwMC0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBU
# aW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDBFWgh2lbgV3eJp01oqiaFBuYbNc7hSKmktvJ15NrB/DBboUow8WPOTPxbn7gc
# mIOGmwJkd+TyFx7KOnzrxnoB3huvv91fZuUugIsKTnAvg2BU/nfN7Zzn9Kk1mpuJ
# 27S6xUDH4odFiX51ICcKl6EG4cxKgcDAinihT8xroJWVATL7p8bbfnwsc1pihZmc
# vIuYGnb1TY9tnpdChWr9EARuCo3TiRGjM2Lp4piT2lD5hnd3VaGTepNqyakpkCGV
# 0+cK8Vu/HkIZdvy+z5EL3ojTdFLL5vJ9IAogWf3XAu3d7SpFaaoeix0e1q55AD94
# ZwDP+izqLadsBR3tzjq2RfrCNL+Tmi/jalRto/J6bh4fPhHETnDC78T1yfXUQdGt
# mJ/utI/ANxi7HV8gAPzid9TYjMPbYqG8y5xz+gI/SFyj+aKtHHWmKzEXPttXzAce
# xJ1EH7wbuiVk3sErPK9MLg1Xb6hM5HIWA0jEAZhKEyd5hH2XMibzakbp2s2EJQWa
# sQc4DMaF1EsQ1CzgClDYIYG6rUhudfI7k8L9KKCEufRbK5ldRYNAqddr/ySJfuZv
# 3PS3+vtD6X6q1H4UOmjDKdjoW3qs7JRMZmH9fkFkMzb6YSzr6eX1LoYm3PrO1Jea
# 43SYzlB3Tz84OvuVSV7NcidVtNqiZeWWpVjfavR+Jj/JOQIDAQABo4IBSTCCAUUw
# HQYDVR0OBBYEFHSeBazWVcxu4qT9O5jT2B+qAerhMB8GA1UdIwQYMBaAFJ+nFV0A
# XmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQ
# Q0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0
# dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIw
# VGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEB
# CwUAA4ICAQCDdN8voPd8C+VWZP3+W87c/QbdbWK0sOt9Z4kEOWng7Kmh+WD2LnPJ
# TJKIEaxniOct9wMgJ8yQywR8WHgDOvbwqdqsLUaM4NrertI6FI9rhjheaKxNNnBZ
# zHZLDwlkL9vCEDe9Rc0dGSVd5Bg3CWknV3uvVau14F55ESTWIBNaQS9Cpo2Opz3c
# RgAYVfaLFGbArNcRvSWvSUbeI2IDqRxC4xBbRiNQ+1qHXDCPn0hGsXfL+ynDZncC
# fszNrlgZT24XghvTzYMHcXioLVYo/2Hkyow6dI7uULJbKxLX8wHhsiwriXIDCnjL
# VsG0E5bR82QgcseEhxbU2d1RVHcQtkUE7W9zxZqZ6/jPmaojZgXQO33XjxOHYYVa
# /BXcIuu8SMzPjjAAbujwTawpazLBv997LRB0ZObNckJYyQQpETSflN36jW+z7R/n
# GyJqRZ3HtZ1lXW1f6zECAeP+9dy6nmcCrVcOqbQHX7Zr8WPcghHJAADlm5ExPh5x
# i1tNRk+i6F2a9SpTeQnZXP50w+JoTxISQq7vBij2nitAsSLaVeMqoPi+NXlTUNZ2
# NdtbFr6Iir9ZK9ufaz3FxfvDZo365vLOozmQOe/Z+pu4vY5zPmtNiVIcQnFy7JZO
# iZVDI5bIdwQRai2quHKJ6ltUdsi3HjNnieuE72fT4eWhxtmnN5HYCDCCB3EwggVZ
# oAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jv
# c29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4
# MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvX
# JHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa
# /rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AK
# OG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rbo
# YiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIck
# w+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbni
# jYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F
# 37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZ
# fD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIz
# GHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR
# /bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1
# Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUC
# AwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0O
# BBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yD
# fQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBN
# MEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoG
# CCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9
# /Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5
# bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvf
# am++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn
# 0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlS
# dYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0
# j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5
# JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakUR
# R6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4
# O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVn
# K+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoI
# Yn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNQMIICOAIBATCB+aGB0aSB
# zjCByzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UE
# CxMcTWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEnMCUGA1UECxMeblNoaWVs
# ZCBUU1MgRVNOOkEwMDAtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQCABol1u1wwwYgUtUowMnqY
# vbul3qCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqG
# SIb3DQEBCwUAAgUA6lw0OTAiGA8yMDI0MDgwNjA1MzM0NVoYDzIwMjQwODA3MDUz
# MzQ1WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDqXDQ5AgEAMAoCAQACAhcLAgH/
# MAcCAQACAhMYMAoCBQDqXYW5AgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQB
# hFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQADggEB
# ACg/vHjHdb3fgAGnGrNZNuHJewiCmyvJj2R1XGy1v9hyABvtmwccDgSaCy5OV6RJ
# epVBlUzFAvLFGRX8dw9ZtYpgiIi1ahpJDVmFWxY5A3p/TB4sNAhCp24RqazzQjwj
# FjUxYjF4KoEE/Nv9tP7oEBjCqIGRZEaG0ExsWbe3pua161vvI24MHEH9/jMwkpXj
# te/6cFJldUSPQpcQV+8N3LYxmNlkzCiYZit6E263wxnAzFr23IDGaKTbGdjJLd4w
# vU6JCDOIvRnStIeWJC8kIwxQjxrGqc8FI5hxMdLX2OaqZwPtFQBr/apn2Po/LO7i
# UH4dCKssQWGJWU9FQTwE1jcxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMAITMwAAAevgGGy1tu847QABAAAB6zANBglghkgBZQMEAgEF
# AKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEi
# BCD6ldw5FAsWcW6zIaIaqxhCtZbuG9E2PIfeD6CJHc+LPzCB+gYLKoZIhvcNAQkQ
# Ai8xgeowgecwgeQwgb0EIM63a75faQPhf8SBDTtk2DSUgIbdizXsz76h1JdhLCz4
# MIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHr4Bhs
# tbbvOO0AAQAAAeswIgQg8TyabVAvVstNRRp9fix2VDnXBAvNfklvJpaxUqeGjuEw
# DQYJKoZIhvcNAQELBQAEggIAbMwqPpZ3qb6PsfODPOkN7hUASidA0CcN3KEkU+cY
# 0pYj68S3Z0mfS7wr27UwZhk8l0UsXMMLCaiW8IKKS/IyMvtsE1XdaH5R+dSmhGaL
# stxnl6tVzYN9MBsMT/k9oRfNPCFG/JxBxDV6bUgo6+mWXHjJc5Ii4S6kGDFssLNp
# iN1vzCRKow1Tl00RosSseW6Upj7WAmBfzqZKvMwXeC1SOeBTDM9Ea9aZ7Y2b3T/z
# G7jQVbcHPUTs8V1QarLi06e3KlRRbGj1USo+pPcXFZkCGkxbjX+DtWAyuLSngJPf
# tlrevoEmeqFe5WyMfE/c1T8NLk4V8G6ZDx/gbkMFzLP7GONrHZnp8aBohb841CFM
# RIhcUW/JcSkjEUcTpGxD7frKmbKkZl/sIZVYcPA47UF62dZpYgMBFY4Ea19WYKex
# yCLCKue87KNUjDNnXCbHBZt9gg5EG8umK3Lbc567JCNJ5nSYYMpGkmra4XFL3+sj
# O35B/nceHKOu0EvMHx58fmQSurf0vZn6nchiv7Js/3Hjd6jvTRcDO4Ga1fgEMxfe
# BhhQpSAX9AK//CTanRJ7zyWmiPjQk3aFOdcNsIJByrU8s/FX9w7hIeJbH2v8ZgCn
# Bj4ZYKl8n44NZDb9GzIqUW0ZTXYxTMFKZzM3aLjheSKhBi+jxico7JJZqsJQZpem
# iGA=
# SIG # End signature block
