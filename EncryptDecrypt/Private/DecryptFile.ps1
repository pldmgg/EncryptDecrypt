<#
    .SYNOPSIS 
    Decrypts a file using AES.

    .DESCRIPTION
    Decrypts a file using an AES key.

    .PARAMETER FileToDecrypt
    File(s) to be decrypted

    .PARAMETER Key
    AES key to be used for decryption.

    .EXAMPLE

    DecryptFile 'C:\file.ext.encrypted' $key

    This example decrypts C:\file.ext.encrypted with the key stored in the variable $key.

    .NOTES
    Author: Tyler Siegrist
    Date: 8/23/2016
    https://gallery.technet.microsoft.com/scriptcenter/EncryptDecrypt-files-use-65e7ae5d
#>
Function DecryptFile {
    Param(
       [Parameter(Mandatory=$true, Position=1)]
       [System.IO.FileInfo[]]$FileToDecrypt,
       [Parameter(Mandatory=$true, Position=2)]
       [String]$Key,
       [Parameter(Mandatory=$false, Position=3)]
       [String]$Suffix
    )
 
    #Load dependencies
    try {
        if ($PSVersionTable.PSEdition -eq "Core") {
            $SystemCoreAssemblyPath = $($(Get-Command pwsh).Source | Split-Path -Parent) + '\System.Core.dll'
            if (!$(Test-Path $SystemCoreAssemblyPath)) {
                Write-Error "The path '$SystemCoreAssemblyPath' was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
            $null = Add-Type -Path $SystemCoreAssemblyPath
        }
        else {
            [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography')
        }
    }
    catch {
        Write-Error 'Could not load required assembly.'
        Return
    }

    #Configure AES
    try {
        $EncryptionKey = [System.Convert]::FromBase64String($Key)
        $KeySize = $EncryptionKey.Length*8
        $AESProvider = New-Object 'System.Security.Cryptography.AesManaged'
        $AESProvider.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $AESProvider.BlockSize = 128
        $AESProvider.KeySize = $KeySize
        $AESProvider.Key = $EncryptionKey
    }
    catch {
        Write-Error 'Unable to configure AES, verify you are using a valid key.'
        Return
    }

    #Used to store successfully decrypted file names.
    $DecryptedFiles = @()
    $FailedToDecryptFiles = @()

    foreach ($File in $FileToDecrypt) {
        # Try to decrypt as long as the .decrypted file doesn't already exist
        $DestinationFile = "$($File.FullName).decrypted"

        if (!$(Test-Path $DestinationFile)) {
            #Open file to decrypt
            try {
                $FileStreamReader = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open)
            }
            catch {
                Write-Error "Unable to open $($File.FullName) for reading."
                Continue
            }
        
            #Create destination file
            try {
                $FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)
            }
            catch {
                $FileStreamReader.Close()
                $FileStreamWriter.Close()
                Remove-Item $DestinationFile -Force
                Write-Error "Unable to open $DestinationFile for writing."
                Continue
            }

            #Get IV
            try {
                [Byte[]]$LenIV = New-Object Byte[] 4
                $FileStreamReader.Seek(0, [System.IO.SeekOrigin]::Begin) | Out-Null
                $FileStreamReader.Read($LenIV,  0, 3) | Out-Null
                [Int]$LIV = [System.BitConverter]::ToInt32($LenIV,  0)
                [Byte[]]$IV = New-Object Byte[] $LIV
                $FileStreamReader.Seek(4, [System.IO.SeekOrigin]::Begin) | Out-Null
                $FileStreamReader.Read($IV, 0, $LIV) | Out-Null
                $AESProvider.IV = $IV
            }
            catch {
                $FileStreamReader.Close()
                $FileStreamWriter.Close()
                Remove-Item $DestinationFile -Force
                $FailedToDecryptFiles += $File
                Write-Error "Unable to read IV from $($File.FullName), verify this file was made using the included EncryptFile function."
                Continue
            }

            Write-Verbose "Decrypting $($File.FullName) with an IV of $([System.Convert]::ToBase64String($AESProvider.IV))"

            #Decrypt
            try {
                $Transform = $AESProvider.CreateDecryptor()
                [Int]$Count = 0
                [Int]$BlockSizeBytes = $AESProvider.BlockSize / 8
                [Byte[]]$Data = New-Object Byte[] $BlockSizeBytes
                $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
                Do
                {
                    $Count = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
                    $CryptoStream.Write($Data, 0, $Count)
                }
                While ($Count -gt 0)

                $CryptoStream.FlushFinalBlock()
                $CryptoStream.Close()
                $FileStreamWriter.Close()
                $FileStreamReader.Close()

                #Delete encrypted file
                Remove-Item $File.FullName
                Write-Verbose "Successfully decrypted $($File.FullName)"
                $DecryptedFiles += $DestinationFile
            }
            catch {
                Write-Error "Failed to decrypt $($File.FullName)."
                $CryptoStream.Close()
                $FileStreamWriter.Close()
                $FileStreamReader.Close()
                Remove-Item $DestinationFile
                $FailedToDecryptFiles += $File
            }
        }        
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType NoteProperty -Name Computer -Value $env:COMPUTERNAME
    $Result | Add-Member -MemberType NoteProperty -Name AESKey -Value $Key
    $Result | Add-Member -MemberType NoteProperty -Name FilesDecryptedwAESKey -Value $DecryptedFiles
    $Result | Add-Member -MemberType NoteProperty -Name FilesFailedToDecrypt -Value $FailedToDecryptFiles
    return $Result
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+Qq9ZQVraxaAi3yRRRoZ2Tzj
# brygggndMIIEJjCCAw6gAwIBAgITawAAAERR8umMlu6FZAAAAAAARDANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE5MTEyODEyMjgyNloXDTIxMTEyODEyMzgyNlowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0crvKbqlk
# 77HGtaVMWpZBOKwb9eSHzZjh5JcfMJ33A9ORwelTAzpRP+N0k/rAoQkauh3qdeQI
# fsqdcrEiingjiOvxaX3lHA5+fVGe/gAnZ+Cc7iPKXJVhw8jysCCld5zIG8x8eHuV
# Z540iNXdI+g2mustl+l5q4kcWukj+iQwtCYEaCgAXB9qlkT33sX0k/07JoSYcGJx
# ++0SHnF0HBw7Gs/lHlyt4biIGtJleOw0iIN2yVD9UrVWMtKrghKPaW31mjYYeN5k
# ckYzBit/Kokxo0m54B4M3aLRPBQdXH1wL6A894BAlUlPM7vrozU2cLrZgcFuEvwM
# 0cLN8mfGKbo5AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAgADMCMGCSsG
# AQQBgjcVAgQWBBQIf0JBlAvGtUeDPLbljq9G8OOkkzAdBgNVHQ4EFgQUkNLPVlgd
# vV0pNGjQxY8gU/mxzMIwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# WObmEzp48rKuXiJ628N7F/clqVVG+dl6UNCrPGK/fr+TbEE3RFpsPfd166gTFF65
# 5ZEbas8qW11makxfIL41GykCZSHMCJBhFhh68xnBSsplemm2CAb06+j2dkuvmOR3
# Aa9+ujtW8eSgNcSr3dkYa3fZfV3siTaY+9FmEWH8D0tglEUuUv1+KPAwXRvdNN7f
# pAsyL5qq/canjqR6/BmLSXdoD3LPISDH/iZpboBwCrhy+imupusnxjZdYFP/Siox
# g7dbvcSkr05t6jlr8xABrU+zzK3yUol/WHOnE70krG3JONBO3kN+Jv/hktIt5pd6
# imtXSPImm4BUPGa7ppeVNDCCBa8wggSXoAMCAQICE1gAAAJQw22Yn6op/pMAAwAA
# AlAwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTkxMTI4MTI1MDM2
# WhcNMjExMTI3MTI1MDM2WjBJMUcwRQYDVQQDEz5aZXJvQ29kZTEzLE9VPURldk9w
# cyxPPVRlY2ggVGFyZ2V0cywgTExDLEw9QnJ5biBNYXdyLFM9UEEsQz1VUzCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPYULq1HCD/SgqTajXuWjnzVedBE
# Nc3LQwdDFmOLyrVPi9S9FF3yYDCTywA6wwgxSQGhI8MVWwF2Xdm+e6pLX+957Usk
# /lZGHCNwOMP//vodJUhxcyDZG7sgjjz+3qBl0OhUodZfqlprcVMQERxlIK4djDoP
# HhIBHBm6MZyC9oiExqytXDqbns4B1MHMMHJbCBT7KZpouonHBK4p5ObANhGL6oh5
# GnUzZ+jOTSK4DdtulWsvFTBpfz+JVw/e3IHKqHnUD4tA2CxxA8ofW2g+TkV+/lPE
# 9IryeA6PrAy/otg0MfVPC2FKaHzkaaMocnEBy5ZutpLncwbwqA3NzerGmiMCAwEA
# AaOCApowggKWMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUW0DvcuEW1X6BD+eQ
# 2AJHO2eur9UwHwYDVR0jBBgwFoAUkNLPVlgdvV0pNGjQxY8gU/mxzMIwgekGA1Ud
# HwSB4TCB3jCB26CB2KCB1YaBrmxkYXA6Ly8vQ049WmVyb1NDQSgyKSxDTj1aZXJv
# U0NBLENOPUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNl
# cyxDTj1Db25maWd1cmF0aW9uLERDPXplcm8sREM9bGFiP2NlcnRpZmljYXRlUmV2
# b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2lu
# dIYiaHR0cDovL3BraS9jZXJ0ZGF0YS9aZXJvU0NBKDIpLmNybDCB5gYIKwYBBQUH
# AQEEgdkwgdYwgaMGCCsGAQUFBzAChoGWbGRhcDovLy9DTj1aZXJvU0NBLENOPUFJ
# QSxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25m
# aWd1cmF0aW9uLERDPXplcm8sREM9bGFiP2NBQ2VydGlmaWNhdGU/YmFzZT9vYmpl
# Y3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MC4GCCsGAQUFBzAChiJodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMykuY3J0MD0GCSsGAQQBgjcVBwQwMC4G
# JisGAQQBgjcVCIO49D+Em/J5g/GPOIOwtzKG0c14gSeh88wfj9lVAgFkAgEFMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMw
# DQYJKoZIhvcNAQELBQADggEBAEfjH/emq+TnlhFss6cNor/VYKPoEeqYgFwzGbul
# dzPdPEBFUNxcreN0b61kxfenAHifvI0LCr/jDa8zGPEOvo8+zB/GWp1Huw/xLMB8
# rfZHBCox3Av0ohjzO5Ac5yCHijZmrwaXV3XKpBncWdC6pfr/O0bIoRMbvV9EWkYG
# fpNaFvR8piUGJ47cLlC+NFTOQcmESOmlsy+v8JeG9OPsnvZLsD6sydajrxRnNlSm
# zbK64OrbSM9gQoA6bjuZ6lJWECCX1fEYDBeZaFrtMB/RTVQLF/btisfDQXgZJ+Tw
# Tjy+YP39D0fwWRfAPSRJ8NcnRw4Ccj3ngHz7e0wR6niCtsMxggH1MIIB8QIBATBU
# MD0xEzARBgoJkiaJk/IsZAEZFgNMQUIxFDASBgoJkiaJk/IsZAEZFgRaRVJPMRAw
# DgYDVQQDEwdaZXJvU0NBAhNYAAACUMNtmJ+qKf6TAAMAAAJQMAkGBSsOAwIaBQCg
# eDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEE
# AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJ
# BDEWBBQFSlLdGmllXjjuRStC9RV0mlb+STANBgkqhkiG9w0BAQEFAASCAQBxoZbE
# 7nodvEk0hJ1U2wUY7kFSc8Ayhg7p25JEW6M3ZtkoCeBc/1rI0XJNtpI0lGI2ys33
# Mhq37Jo+MsL8P3AwDGjXwXUfbBvdAsYQErizPhWPmdhfIaanaQN9fYD+uhtDPrPZ
# TgfEX6WZ7sA0C25qLd4IXdPO7nhnGvqaGb25EeoubUFTNn0SU0eK8U+UwojQOR5n
# z2NFmImwHr0sJxgylXrNmdHhaxmT62DRtFIghxvTFzFrebAstVBsU7h4pq4YiMIz
# R1Xx9s42uuvL21P0mr8nSyJq6k1dVxijBOrOPKtfU5+aEdsCtdYujYkhLfs172bH
# W1ehkJTsk1A/+L+P
# SIG # End signature block
