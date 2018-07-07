<#
    .SYNOPSIS 
    Generates a random cryptography key.

    .DESCRIPTION
    Generates a random cryptography key based on the desired key size.

    .PARAMETER Algorithm
    Algorithm to generate key for.

    .PARAMETER KeySize
    Number of bits the generated key will have.

    .PARAMETER AsPlainText
    Returns a String instead of SecureString.

    .OUTPUTS
    System.Security.SecureString. New-CryptographyKey return the key as a SecureString by default.
    System.String. New-CryptographyKey will return the key in plain text as a string if the -AsPlainText parameter is specified.

    .EXAMPLE
    $key = New-CryptographyKey
    This example generates a random 256-bit AES key and stores it in the variable $key.

    .NOTES
    Author: Tyler Siegrist
    Date: 9/22/2017
#>
function NewCryptographyKey() {
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    [OutputType([String], ParameterSetName='PlainText')]
    Param(
        [Parameter(Mandatory=$false, Position=1)]
        [ValidateSet('AES','DES','RC2','Rijndael','TripleDES')]
        [String]$Algorithm='AES',
        [Parameter(Mandatory=$false, Position=2)]
        [Int]$KeySize,
        [Parameter(ParameterSetName='PlainText')]
        [Switch]$AsPlainText
    )
    Process
    {
        try
        {
            $Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create($Algorithm)
            if($PSBoundParameters.ContainsKey('KeySize')){
                $Crypto.KeySize = $KeySize
            }
            $Crypto.GenerateKey()
            if($AsPlainText)
            {
                return [System.Convert]::ToBase64String($Crypto.Key)
            }
            else
            {
                return [System.Convert]::ToBase64String($Crypto.Key) | ConvertTo-SecureString -AsPlainText -Force
            }
        }
        catch
        {
            Write-Error $_
        }
    }
}