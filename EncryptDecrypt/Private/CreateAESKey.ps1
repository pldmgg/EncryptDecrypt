<#
    .SYNOPSIS 
    Generates a random AES key.

    .DESCRIPTION
    Generates a random AES key based on the desired key size.

    .PARAMETER KeySize
    Number of bits the generated key will have.

    .EXAMPLE

    $key = CreateAESKey

    This example generates a random 256-bit AES key and stores it in the variable $key.

    .NOTES
    Author: Tyler Siegrist
    Date: 8/23/2016
    https://gallery.technet.microsoft.com/scriptcenter/EncryptDecrypt-files-use-65e7ae5d
#>
function CreateAESKey() {
    Param(
       [Parameter(Mandatory=$false, Position=1, ValueFromPipeline=$true)]
       [Int]$KeySize=256
    )

    try {
        $AESProvider = New-Object "System.Security.Cryptography.AesManaged"
        $AESProvider.KeySize = $KeySize
        $AESProvider.GenerateKey()
        return [System.Convert]::ToBase64String($AESProvider.Key)
    }
    catch {
        Write-Error $_
    }
}