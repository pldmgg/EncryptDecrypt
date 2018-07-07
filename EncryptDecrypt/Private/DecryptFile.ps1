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
        [System.Reflection.Assembly]::LoadWithPartialName('System.Security.Cryptography')
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

    Write-Verbose "Encryping $($FileToDecrypt.Count) File(s) with the $KeySize-bit key $Key"

    #Used to store successfully decrypted file names.
    $DecryptedFiles = @()
    $FailedToDecryptFiles = @()

    foreach ($File in $FileToDecrypt) {
        #Verify filename
        <#
        if(-not $File.Name.EndsWith($Suffix)) {
            Write-Error "$($File.FullName) does not have an extension of '$Suffix'."
            Continue
        }
        #>

        #Open file to decrypt
        try {
            $FileStreamReader = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open)
        }
        catch {
            Write-Error "Unable to open $($File.FullName) for reading."
            Continue
        }
    
        #Create destination file
        $DestinationFile = "$($File.FullName).decrypted"
        try {
            $FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)
        }
        catch {
            Write-Error "Unable to open $DestinationFile for writing."
            $FileStreamReader.Close()
            $FileStreamWriter.Close()
            Remove-Item $DestinationFile -Force
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
            Write-Warning "Unable to read IV from $($File.FullName), verify this file was made using the included EncryptFile function."
            $FileStreamReader.Close()
            $FileStreamWriter.Close()
            Remove-Item $DestinationFile -Force
            $FailedToDecryptFiles += $File
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

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType NoteProperty -Name Computer -Value $env:COMPUTERNAME
    $Result | Add-Member -MemberType NoteProperty -Name AESKey -Value $Key
    $Result | Add-Member -MemberType NoteProperty -Name FilesDecryptedwAESKey -Value $DecryptedFiles
    $Result | Add-Member -MemberType NoteProperty -Name FilesFailedToDecrypt -Value $FailedToDecryptFiles
    return $Result
}