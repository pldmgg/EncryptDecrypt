<#
    .SYNOPSIS 
    Encrypts a file using AES.

    .DESCRIPTION
    Encrypts a file using an AES key.

    .PARAMETER FileToEncrypt
    File(s) to be encrypted

    .PARAMETER Key
    AES key to be used for encryption.

    .EXAMPLE

    $key = NewCryptographyKey -AsPlainText
    EncryptFile 'C:\file.ext' $key

    This example encrypts C:\file.ext with the key stored in the variable $key.

    .NOTES
    Author: Tyler Siegrist
    Date: 8/23/2016
    https://gallery.technet.microsoft.com/scriptcenter/EncryptDecrypt-files-use-65e7ae5d
#>
Function EncryptFile {
    Param(
       [Parameter(Mandatory=$true, Position=1)]
       [System.IO.FileInfo[]]$FileToEncrypt,
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

    Write-Verbose "Encryping $($FileToEncrypt.Count) File(s) with the $KeySize-bit key $Key"

    #Used to store successfully encrypted file names.
    $EncryptedFiles = @()
    
    foreach ($File in $FileToEncrypt) {
        <#
        if ($File.Name.EndsWith($Suffix)) {
            Write-Error "$($File.FullName) already has a suffix of '$Suffix'."
            Continue
        }
        #>

        #Open file to encrypt
        try {
            $FileStreamReader = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open)
        }
        catch {
            Write-Error "Unable to open $($File.FullName) for reading."
            Continue
        }

        #Create destination file
        $DestinationFile = "$($File.FullName).aesencrypted"
        try {
            $FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)
        }
        catch {
            Write-Error "Unable to open $DestinationFile for writing."
            $FileStreamReader.Close()
            Continue
        }
    
        #Write IV length & IV to encrypted file
        $AESProvider.GenerateIV()
        $FileStreamWriter.Write([System.BitConverter]::GetBytes($AESProvider.IV.Length), 0, 4)
        $FileStreamWriter.Write($AESProvider.IV, 0, $AESProvider.IV.Length)

        Write-Verbose "Encrypting $($File.FullName) with an IV of $([System.Convert]::ToBase64String($AESProvider.IV))"

        #Encrypt file
        try {
            $Transform = $AESProvider.CreateEncryptor()
            $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
            [Int]$Count = 0
            [Int]$BlockSizeBytes = $AESProvider.BlockSize / 8
            [Byte[]]$Data = New-Object Byte[] $BlockSizeBytes
            do {
                $Count = $FileStreamReader.Read($Data, 0, $BlockSizeBytes)
                $CryptoStream.Write($Data, 0, $Count)
            }
            while ($Count -gt 0)
    
            #Close open files
            $CryptoStream.FlushFinalBlock()
            $CryptoStream.Close()
            $FileStreamReader.Close()
            $FileStreamWriter.Close()

            #Delete unencrypted file
            Remove-Item $File.FullName
            Write-Verbose "Successfully encrypted $($File.FullName)"
            $EncryptedFiles += $DestinationFile
        }
        catch {
            Write-Error "Failed to encrypt $($File.FullName)."
            $CryptoStream.Close()
            $FileStreamWriter.Close()
            $FileStreamReader.Close()
            Remove-Item $DestinationFile
        }
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType NoteProperty -Name Computer -Value $env:COMPUTERNAME
    $Result | Add-Member -MemberType NoteProperty -Name AESKey -Value $Key
    $Result | Add-Member -MemberType NoteProperty -Name FilesEncryptedwAESKey -Value $EncryptedFiles
    return $Result
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUcEZo0Mf0ZJHaqoaGaZ+oIAax
# eoegggndMIIEJjCCAw6gAwIBAgITawAAAERR8umMlu6FZAAAAAAARDANBgkqhkiG
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
# BDEWBBS5Y07PVj8QulbPBW+WSexpF/O3KDANBgkqhkiG9w0BAQEFAASCAQA75pw8
# hiaFAR6LFbRTVsJvc4pVCRfmG4CRiJ2+HBcVDiZ9rlE7EksWi4Z4r+SIXGN2oP2N
# FKn+2pMepx8hgvR4hBuGXDiTAa56tQS89R3GLsNpyApnRpFFpSBGog6X/o3xAMCF
# kYfBeKSScxThXC8gLUwkQGwoWrVjB9uQFZYY1vcSlLHtVQMRa3qsjQYQbiEZz3lU
# sczryJDSZdlgiVqR3weHcxQdOb/c9HMHkiNEkPo5txYVGi47Walj9WjW2SrU5cV0
# FfAndE5M5a9CjgM+fak0RxiH3VcPRdpNShK93zrxo/IApwOsTSX16X8PuglC3tOP
# sN+uxdwx2wA4MIrI
# SIG # End signature block
