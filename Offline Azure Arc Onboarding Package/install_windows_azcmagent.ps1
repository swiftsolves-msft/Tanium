#Requires -Version 4.0
#Requires -RunAsAdministrator

[CmdletBinding()]
param (
    [string]$OutFile,
    [string]$AltDownload,
    [string]$Proxy    
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$refVersion = [version] '4.5'

# Error codes used by azcmagent are in range of [0, 125].
# Installation scripts will use [127, 255]. Check install_linux_azcmagent.sh for the codes used for Linux script.
$global:errorcode="AZCM0150"

# Ensure TLS 1.2 is accepted. Older PowerShell builds (sometimes) complain about the enum "Tls12" so we use the underlying value
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
# Ensure TLS 1.3 is accepted, if this .NET supports it (older versions don't)
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 12288 } catch {}
    
function Test-AzureStackHCI() {
    [CmdletBinding()]
    param (
    )

    try {
        $product=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName | select -ExpandProperty ProductName
    }
    catch {
        Write-Verbose -Message "Error $_ Unable to determine product SKU from registry" -Verbose
        # Will attempt to install anyway
        return $false
    }
    if ($product -eq 'Azure Stack HCI') {
        return $true
    }
    return $false
}

function Test-DotNetFramework() {
    [CmdletBinding()]
    param (
    )

    try {
        $installedVersion = [version] (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Version | select -ExpandProperty Version)
    }
    catch {
        Write-Verbose -Message "Error $_ Unable to determine .NET Framework version" -Verbose
        # Will attempt to install anyway
        return $true
    }
    Write-Verbose -Message ".NET Framework version: $installedVersion" -Verbose
    if ($installedVersion -ge $refVersion) {
        return $true
    }
    return $false
}

function Test-IsAzure() {
    [CmdletBinding()]
    param (
    )

    Write-Verbose "Checking if this is an Azure virtual machine"
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri "http://169.254.169.254/metadata/instance/compute?api-version=2019-06-01" -Headers @{Metadata = "true"} -TimeoutSec 1 -ErrorAction SilentlyContinue
    }
    catch {
        Write-Verbose "Error $_ checking if we are in Azure"
        return $false
    }
    if ($null -ne $response -and $response.StatusCode -eq 200) {
        Write-Verbose "Azure check indicates that we are in Azure"
        return $true
    }
    return $false
}

function Get-MsiLogSummary() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogPath
    )

    try
    {
        $LogPath = Resolve-Path $LogPath
        Write-Verbose "Reading Logs from $LogPath"

        $patterns = @(
            "Installation success or error status",
            "Product: Azure Connected Machine Agent"
        );

        $regex = "(" + ($patterns -join ")|(" ) + ")"

        Write-Verbose "Looking for Patterns: $regex"

        $inCustomAction = $false
        $logCustomAction = $false
        $caOutput = new-object -TypeName System.Collections.ArrayList
        Get-Content $LogPath | % {
            # log interesting lines
            if ( ($_ -match $regex)) {
                $_ # output to pipeline
            }

            # Wix custom actions start with "Calling custom Action". Gather the log from the CA till we see if it passed
            # At the end, log that output only if it failed with "returned actual error"
            if ($_ -match "Calling custom action") {
                $inCustomAction = $true
                $logCustomAction = $false
            }
            if ($_ -match "MSI \(s\)") {
                $inCustomAction = $false 
            }
            if ($_ -match "returned actual error") {
                $logCustomAction = $true
            }
            if ($inCustomAction) {
                $null = $caOutput.Add($_)
            }
            else
            {
                if($logCustomAction) {
                    $caOutput # output saved lines to pipeline
                }
                $caOutput.Clear()
            }
        }
    } catch {
        # This code is optional so if something goes wrong we'll just swallow the error and have no details
        Write-Verbose "Error while parsing MSI log: $_"
    }
}

<# Throw a structured exception#>
function Invoke-Failure
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        $Message,
        [Parameter(Mandatory=$true)]
        $ErrorCode,
        [Parameter(Mandatory=$false)]
        $Details
    )

    $ex = new-object -TypeName System.Exception -ArgumentList @($Message)
    $ex.Data["Details"] = $details
    $ex.Data["ErrorCode"] = $errorcode
    throw $ex
}

function Send-Failure
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Exception] $Error,

        [Parameter(Mandatory = $true)]
        [string] $ErrorCode
    )

    $hisEndpoint = "https://gbl.his.arc.azure.com"
    if ($env:CLOUD -eq "AzureUSGovernment") {
        $hisEndpoint = "https://gbl.his.arc.azure.us"
    } elseif ($env:CLOUD -eq "AzureChinaCloud") {
        $hisEndpoint = "https://gbl.his.arc.azure.cn"
    }

    $message = "$Error"
    if ($Error.Data["Details"]) {
        $message = $Error.Data["Details"]
    }
    $message = $message.Substring(0, [Math]::Min($message.Length, 600))

    $logBody = @{subscriptionId="$env:SUBSCRIPTION_ID";resourceGroup="$env:RESOURCE_GROUP";tenantId="$env:TENANT_ID";location="$env:LOCATION";correlationId="$env:CORRELATION_ID";authType="$env:AUTH_TYPE";operation="onboarding";messageType="$ErrorCode";message="$message";}
    #Invoke-WebRequest -UseBasicParsing -Uri "$hisEndpoint/log" -Method "PUT" -Body ($logBody | ConvertTo-Json) -ErrorAction SilentlyContinue | out-null
    $logBody | ConvertTo-Json | Out-File arc.log
}

function Check-Physical-Memory() {
    [CmdletBinding()]
    param (
    )

    $memory = systeminfo | Select-String '^Total Physical Memory'
    Write-Verbose -Message "$memory" -Verbose
}

try {
    Write-Verbose -Message "Installing Azure Connected Machine Agent" -Verbose

    Check-Physical-Memory
    $hci = Test-AzureStackHCI
    if ($hci) {
        Invoke-Failure -Message "This server is running Azure Stack HCI and should be connected to Azure Arc using the built-in registration experience: https://aka.ms/install-arc-on-hci-host" -ErrorCode "AZCM0152"
    }
    
    $validFramework = Test-DotNetFramework
    if (-Not $validFramework) {
        Invoke-Failure -Message "Azure Connected Machine Agent requires .NET Framework version $refVersion or later" -ErrorCode "AZCM0151"
    }
    
    $inAzure = Test-IsAzure
    if ($inAzure) {
        $override = [System.Environment]::GetEnvironmentVariable("MSFT_ARC_TEST", [System.EnvironmentVariableTarget]::Machine)
        if ('true' -eq $override) {
            Write-Warning '''Running on an Azure Virtual Machine with MSFT_ARC_TEST set.
Azure Connected Machine Agent is designed for use outside Azure.
This virtual machine should only be used for testing purposes.
See https://aka.ms/azcmagent-testwarning for more details.
'''
        } else {
            Invoke-Failure -ErrorCode "AZCM0147" -Message '''Cannot install Azure Connected Machine agent on an Azure Virtual Machine.
Azure Connected Machine Agent is designed for use outside Azure.
To connect an Azure VM for TESTING PURPOSES ONLY, see https://aka.ms/azcmagent-testwarning for more details.
'''
        }
    }

    # variable the package
    $msiFile = "AzureConnectedMachineAgent.msi"
        
    # Install the package
    $logFile = "installationlog.txt"
    Write-Verbose -Message "Installing agent package" -Verbose
    $exitCode = (Start-Process -FilePath msiexec.exe -ArgumentList @("/i", $msiFile, "/l*v", $logFile, "/qn") -Wait -Passthru).ExitCode
    if ($exitCode -ne 0) {
        $message = (net helpmsg $exitCode)
        $details = ((Get-MsiLogSummary $logFile) -join "`n")
        Invoke-Failure -Message "Installation failed: $message`: See $logFile for additional details." -ErrorCode "AZCM0149" -Details $details
    }

    # Check if we need to set proxy environment variable
    if ($Proxy) {
        Write-Verbose -Message "Setting proxy configuration: $Proxy" -Verbose
        & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent" config set proxy.url ${Proxy}
    }
    
} catch {
    $code = $_.Exception.Data.ErrorCode
    if(!$code) { $code = "AZCM0150" } # default if we do not have some more specific error 
    if ($OutFile) {
        [ordered]@{
            status  = "failed"
            error = [ordered]@{
                message = $_.Exception.Message
                code = $code
                details = $_.Exception.Data.Details
            }
        } | ConvertTo-Json | Out-File $OutFile
    }
    Write-Error $_ -ErrorAction Continue
    Send-Failure $_.Exception $code
    exit 1
}

# Installation was successful if we got this far
if ($OutFile) {
    [ordered]@{
        status  = "success"
        message = "Installation of azcmagent completed successfully"
    } | ConvertTo-Json | Out-File $OutFile
}

Write-Host "Installation of azcmagent completed successfully"

exit 0
# SIG # Begin signature block
# MIInngYJKoZIhvcNAQcCoIInjzCCJ4sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAoBc7k+DbrpPzZ
# TiUOxqzUiMCasYUqDDNqoTNNz5eCuKCCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZczCCGW8CAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgJNpX/J7f
# 8AnILVDwDVIKsecw3MWlBjbrRWm4ye4xLuEwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQB2FoW0IgwDLFLjqYyjtYtTS5vCW32UF6jVa8IQM2r+
# AryFNrm1SBzIHSUW/eOl55k81xdL4xpIAgm4Tsuo+KtlF+dGsI9xzqL7IKxhr/0f
# MZ9IpdttcRTwnuncLwcWnVGLMuLtRRHgCTQyXeNkeop87dLlNO0MxhrI1nAVDj2j
# Y9RY0YEgY/xu19LvtZym/lMNXnrUy4O1NZnvQmsjgFFGLteLPUTCoOoTvcmtryUV
# W9hOPhwBnVZCxoMbKhmdpD1ET9IwstyXOd8oXNR0lPGCLHzbCBWCam7240x/7bt7
# /sRgfnCVkw5i+JNBs+4YLyVnN5HngD7GvHiGz272vstyoYIW/TCCFvkGCisGAQQB
# gjcDAwExghbpMIIW5QYJKoZIhvcNAQcCoIIW1jCCFtICAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIM5MVlNU7LW8v+sdAj3CShtwUcW+du4+EATbNErf
# ZS/CAgZjbP9SdysYEzIwMjIxMTI5MTk0MjE1LjIzMlowBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNVBAsTHE1p
# Y3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOjdCRjEtRTNFQS1CODA4MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIRVDCCBwwwggT0oAMCAQICEzMAAAHI+bDuZ+3qa0YAAQAAAcgw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MjIxMTA0MTkwMTM3WhcNMjQwMjAyMTkwMTM3WjCByjELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFtZXJpY2Eg
# T3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046N0JGMS1FM0VBLUI4
# MDgxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC5y51+KE+DJFbCeci4kKpzdMK0WTRc
# 6KYVwqNT1tLpYWeDaX4WsiJ3SY9nspazoTCPbVf5mQaQzrH6jMeWY22cdJDjymMg
# V2UpciiHt9KjjUDifS1AiXCGzy4hgihynvbHAMEcpJnEZoRr/TvTuLI7D5pdlc1x
# PGA2JEQBJv22GUtkzvmZ8kiAFW9SZ0tlz5c5RjDP/y6XsgTO080fhyfwKfS0mEgV
# +nad62vwZg2iLIirG54bv6xK3bFeXv+KBzlwc9mdaF+X09oHj5K62sDzMCHNUdOe
# PhF9/EDhHeTgFFs90ajBB85/3ll5jEtMd/lrAHSepnE5j7K4ZaF/qGnlEZGi5z1t
# 5Vm/3wzV6thrnlLVqFmAYNAnJxW0TLzZGWYp9Nhja42aU8ta2cPuwOWlWSFhAYq5
# Nae7BAqr1lNIT7RXZwfwlpYFglAwi5ZYzze8s+jchP9L/mNPahk5L2ewmDDALBFS
# 1i3C2rz88m2+3VXpWgbhZ3b8wCJ+AQk6QcXsBE+oj1e/bz6uKolnmaMsbPzh0/av
# Kh7SXFhLPc9PkSsqhLT7Mmlg0BzFu/ZReJOTdaP+Zne26XPrPhedKXmDLQ8t6v4R
# WPPgb3oZxmArZ30b65jKUdbAGd4i/1gVCPrIx1b/iwSmQRuumIk16ZzFQKYGKlnt
# Jzfmu/i62Qnj9QIDAQABo4IBNjCCATIwHQYDVR0OBBYEFLVcL0mButLAsNOIklPi
# Irs1S+T1MB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01p
# Y3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEF
# BQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZI
# hvcNAQELBQADggIBAMPWclLIQ8OpKCd+QWJ8hu14lvs2RkJtGPnIEaJPV/19Ma9R
# vkJbuTd5Kne7FSqib0tbKRw19Br9h/DSWJsSKb1hGNQ1wvjaggWq2n/uuX2CDrWi
# IHw8H7q8sSaNeRjFRRHxaMooLlDl3H3oHbV9pJyjYw6a+NjEZRHsCf7jnb2VA88u
# psQpGNw1Bv6n6aRAfZd4xuyHkRAKRO5gCKYVOCe6LZk8UsS4GnEErnPYecqd4dQn
# 2LilwpZ0KoXUA5U3yBcgfRHQV+UxwKDlNby/3RXDH+Y/doTYiB7W4Twz1g0Gfnvv
# o/GYDXpn5zaz6Fgj72wlmGFEDxpJhpyuUvPtpT/no68RhERFBm224AWStX4z8n60
# J4Y2/QZ3vljiUosynn/TGg6+I8F0HasPkL9T4Hyq3VsGpAtVnXAdHLT/oeEnFs6L
# YiAYlo4JgsZfbPPRUBPqZnYFNasmZwrpIO/utfumyAL4J/W3RHVpYKQIcm2li7Iq
# N/tSh1FrN685/pXTVeSsBEcqsjttCgcUv6y6faWIkIGM3nWYNagSBQIS/AHeX5EV
# gAvRoiKxzlxNoZf9PwX6IBvP6PYYZW6bzmARBL24vNJ52hg/IRfFNuXB7AZ0DGoh
# loqjNEGjDj06cv7kKCihUx/dlKqnFzZALQTTeXpz+8KGRjKoxersvB3g+ceqMIIH
# cTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
# TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEw
# OTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQ
# Q0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIh
# C3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNx
# WuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFc
# UTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAc
# nVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUo
# veO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyzi
# YrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9
# fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdH
# GO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7X
# KHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiE
# R9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/
# eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3
# FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAd
# BgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEE
# AYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMB
# Af8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1Ud
# HwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3By
# b2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQRO
# MEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2Vy
# dHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4IC
# AQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pk
# bHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gng
# ugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3
# lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHC
# gRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6
# MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEU
# BHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvsh
# VGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+
# fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrp
# NPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHI
# qzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAsswggI0AgEBMIH4
# oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4G
# A1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSUw
# IwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjo3QkYxLUUzRUEtQjgwODElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA384TULvGNTQKUgNd
# AGK5wBjuy7KggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAN
# BgkqhkiG9w0BAQUFAAIFAOcwifAwIhgPMjAyMjExMjkyMTM4NTZaGA8yMDIyMTEz
# MDIxMzg1NlowdDA6BgorBgEEAYRZCgQBMSwwKjAKAgUA5zCJ8AIBADAHAgEAAgIN
# bDAHAgEAAgIRVTAKAgUA5zHbcAIBADA2BgorBgEEAYRZCgQCMSgwJjAMBgorBgEE
# AYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEBBQUAA4GB
# ABMUmXasb6AveeOkT8OmSd/U+73ydeh8zZOGsskNaCm6pu8Ep8LWcHbVxN5qiQoO
# MbldEs+EzV6Mpb/VatyV4/rmUhrj9o/RJjymk5vtQXRGiXnngNc/s/DsIYf90X5e
# JDCCxrf7xf08qZsldgWca0k4fYfvj+/IjlaNcGJm2W7SMYIEDTCCBAkCAQEwgZMw
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHI+bDuZ+3qa0YAAQAA
# AcgwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRAB
# BDAvBgkqhkiG9w0BCQQxIgQgHLx73/lJ83Ld5mH8razmVZLGVdnJhdVFbnaHy4Sw
# JZIwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBiAJjPzT9toy/HDqNypK8v
# QVbhN28DT2fEd+w+G4QDZjCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAAByPmw7mft6mtGAAEAAAHIMCIEIJOT4mieVc7mfbD4gJC26XDX
# oOQqmyDkRRYlXHbLBQKEMA0GCSqGSIb3DQEBCwUABIICABn04utzBsA2v2OzqdI7
# Qz4I1/1PYMXkx+WVHr5tCNarxIHk0sG52Ras+P50h9S0JBh9d0dy0ruTFt/3n8OK
# PHS3TExeBN0zHRSTTJlG/yvxdPv+8qx9nusi5RrtQ+egW6+ikwgMKoHJU/BJNIRV
# H0I8zoTnmahFzmk8f+FaTCvHdtz0EJjf0regAW5YKubf0zmh33RfVYhxOmlA5bmE
# m0xgILGFhlHRA6lo76cOu3eRhQXX3e0e8rLSZ0psZCquBr/VyulEw20MiqWXjQx1
# zGPNPjDsOBitEqkwkTD1NmY3Ril22sEI7e89b8SBlzZxf1CspnDabPzXZo72sM/n
# xzRey3Z8Um3wZdy68N4qz0tjz9xUv3kO/5iVcKPrzMbtwx9fq7a/UvEW3YZC0Ogd
# 6x/jgT9nFuxyRnMiqFTZIUYLpp3OiMUxGBtcpL1Q8/E6mOULit/B5Q7qcvUrda7v
# DhhkKLHumu2UOEk0aZkd2N6keRPIb8wn0WopJxXchcAkReTcwIVUZ29dxnxYL33z
# 2J9TVGkEBeN61Ls6rw1XJ3JlV+X2sFjGxuiHADU/vWIQuHcmqn8MitHdaLQ5befM
# KBjQds+JaWNI79cWYm+t6WzZFuOpyRPMhfS07YNAxOvOQc9Of0RI7x4CQHr+XxmH
# EuZekSf4Uug5BGip1Wzeymt8
# SIG # End signature block
