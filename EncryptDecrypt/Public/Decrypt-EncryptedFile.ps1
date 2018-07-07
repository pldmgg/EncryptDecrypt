<#
    .SYNOPSIS
        This function decrypts a String, an Array of Strings, a File, or Files in a Directory that were encrypted using the
        New-EncryptedFile function.

    .DESCRIPTION
        See SYNOPSIS.

    .NOTES
        IMPORTANT NOTES:
        This function identifies a file as RSA encrypted or AES encrypted according to the file's extension. For example,
        a file with an extension ".rsaencrypted" is identified as encrypted via RSA. A file with an extension ".aesencrypted"
        is identified as encrypted via AES. If the file(s) you intend to decrypt do not have either of these file extensions,
        or if you are decrypting a String or ArrayOfStrings in an interactive PowerShell Session, then you can use the
        -TypeOfEncryptionUsed parameter and specify either "RSA" or "AES".

        If the -TypeOfEncryptionUsed parameter is NOT used and -ContentType is "String" or "ArrayOfStrings", RSA decryption
        will be used.
        If the -TypeOfEncryptionUsed parameter is NOT used and -ContentType is "File", AES decryption will be used.
        If the -TypeOfEncryptionUsed parameter is NOT used and -ContentType is "Directory", both RSA and AES decryption will be
        attempted on each file.

    .PARAMETER ContentType
        Mandatory.

        This parameter takes a string with one of the following values:
            String
            ArrayOfStrings
            File
            Directory

        If -ContentToEncrypt is a string, -ContentType should be "String".
        If -ContentToEncrypt is an array of strings, -ContentType should be "ArrayOfStrings".
        If -ContentToEncrypt is a string that represents a full path to a file, -ContentType should be "File".
        If -ContentToEncrypt is a string that represents a full path to a directory, -ContentType should be "Directory".

    .PARAMETER ContentToEncrypt
        Mandatory.

        This parameter takes a string that is either:
            - A string
            - An array of strings
            - A string that represents a full path to a file
            - A string that represents a full path to a directory

    .PARAMETER Recurse
        Optional.

        This parameter is a switch. It should only be used if -ContentType is "Directory". The function will fail
        immediately if this parameter is used and -ContentType is NOT "Directory".

        If this switch is NOT used, only files immediately under the directory specified by -ContentToEncrypt are
        decrypted.

        If this switch IS used, all files immediately under the directory specified by -ContentToEncrypt AS WELL AS
        all files within subdirectories under the directory specified by -ContentToEncrypt are decrypted.

    .PARAMETER FileToOutput
        Optional.

        This parameter specifies a full path to a NEW file that will contain decrypted information. This parameter should
        ONLY be used if -ContentType is "String" or "ArrayOfStrings". If this parameter is used and -ContentType is NOT
        "String" or "ArrayOfStrings", the function will immediately fail.

    .PARAMETER PathToCertFile
        Optional. (However, either -PathToCertFile or -CNOfCertInStore are required.)

        This parameter takes a string that represents the full path to a .pfx file that was used for encryption. The
        private key in the .pfx file will be used for decryption.

        NOTE: RSA decryption is ALWAYS used by this function, either to decrypt the information directly or to decrypt the
        AES Key that was used to encrypt the information originally so that it can be used in AES Decryption.

    .PARAMETER CNOfCertInStore
        Optional. (However, either -PathToCertFile or -CNOfCertInStore are required.)

        This parameter takes a string that represents the Common Name (CN) of the certificate that was used for RSA
        encryption. This certificate must already exist in the Local Machine Store (i.e. Cert:\LocalMachine\My). The
        private key in the certificate will be used for decryption.

        NOTE: RSA decryption is ALWAYS used by this function, either to decrypt the information directly or to decrypt the
        AES Key that was used to encrypt the information originally so that it can be used in AES Decryption.

    .PARAMETER CertPwd
        Optional. (However, this parameter is mandatory if the certificate is password protected).

        This parameter takes a System.Security.SecureString that represents the password for the certificate.

        Use this parameter if the certificate is password protected.

    .PARAMETER TypeOfEncryptionUsed
        Optional.

        This parameter takes a string with value of either "RSA" or "AES".

        If you want to force this function to use a particular type of decryption, use this parameter.

        If this parameter is NOT used and -ContentType is "String" or "ArrayOfStrings", RSA decryption will be used.
        If this parameter is NOT used and -ContentType is "File", AES decryption will be used.
        If this parameter is NOT used and -ContentType is "Directory", both RSA and AES decryption will be attempted
        on each file.

    .PARAMETER AESKey
        Optional.

        This parameter takes a Base64 string that represents the AES Key used for AES Encryption. This same key will be used
        for AES Decryption.

    .PARAMETER AESKeyLocation
        Optional.

        This parameter takes a string that represents a full file path to a file that contains the AES Key originally used
        for encryption. 

        If the file extension ends with ".rsaencrypted", this function will use the specified Certificate
        (i.e. the certificate specified via -PathToCertFile or -CNOfCertInStore parameters, specifically the private key
        contained therein) to decrypt the file, revealing the base64 string that represents the AES Key used for AES Encryption.

        If the file extension does NOT end with ".rsaencrypted", the function will assume that the the file contains the
        Base64 string that represents the AES key originally used for AES Encryption.

    .PARAMETER NoFileOutput
        Optional.

        This parameter is a switch. If you do NOT want decrypted information written to a file, use this parameter. The
        decrypted info will ONLY be written to console as part of the DecryptedContent Property of the PSCustomObject output.

    .EXAMPLE
        # Decrypting an Encrypted String without File Outputs
        PS C:\Users\zeroadmin> $EncryptedStringTest = Get-Content C:\Users\zeroadmin\other\MySecret.txt.rsaencrypted
        PS C:\Users\zeroadmin> Decrypt-EncryptedFile -ContentType String -ContentToDecrypt $EncryptedStringTest -PathToCertFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -NoFileOutput

        Doing RSA Decryption

        DecryptedFiles                     :
        FailedToDecryptFiles               : {}
        CertUsedDuringDecryption           : [Subject]
                                            CN=ArrayOfStrings

                                            [Issuer]
                                            CN=ArrayOfStrings

                                            [Serial Number]
                                            32E38D18591854874EC467B73332EA76

                                            [Not Before]
                                            6/1/2017 4:13:36 PM

                                            [Not After]
                                            6/1/2018 4:33:36 PM

                                            [Thumbprint]
                                            C8CC2B8B03E33821A69B35F10B04D74E40A557B2

        PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\PrivateKeyExtractionTempDir\ArrayOfStrings.pfx
        LocationOfCertUsedDuringDecryption : C:\Users\zeroadmin\other\ArrayOfStrings.pfx
        UnprotectedAESKey                  :
        LocationOfAESKey                   :
        AllFileOutputs                     :
        DecryptedContent                   : THisISmYPWD321!

    .EXAMPLE
        # Decrypting an Array Of Strings without File Outputs
        PS C:\Users\zeroadmin> $enctext0 = Get-Content C:\Users\zeroadmin\other\ArrayOfStrings.txt0.rsaencrypted
        PS C:\Users\zeroadmin> $enctext1 = Get-Content C:\Users\zeroadmin\other\ArrayOfStrings.txt1.rsaencrypted
        PS C:\Users\zeroadmin> $enctext2 = Get-Content C:\Users\zeroadmin\other\ArrayOfStrings.txt2.rsaencrypted
        PS C:\Users\zeroadmin> $enctextarray = @($enctext0,$enctext1,$enctext2)
        PS C:\Users\zeroadmin> Decrypt-EncryptedFile -ContentType ArrayOfStrings -ContentToDecrypt $enctextarray -PathToCertFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -NoFileOutput
        Doing RSA Decryption


        DecryptedFiles                     :
        FailedToDecryptFiles               : {}
        CertUsedDuringDecryption           : [Subject]
                                            CN=ArrayOfStrings

                                            [Issuer]
                                            CN=ArrayOfStrings

                                            [Serial Number]
                                            32E38D18591854874EC467B73332EA76

                                            [Not Before]
                                            6/1/2017 4:13:36 PM

                                            [Not After]
                                            6/1/2018 4:33:36 PM

                                            [Thumbprint]
                                            C8CC2B8B03E33821A69B35F10B04D74E40A557B2

        PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\PrivateKeyExtractionTempDir\ArrayOfStrings.pfx
        LocationOfCertUsedDuringDecryption : C:\Users\zeroadmin\other\ArrayOfStrings.pfx
        UnprotectedAESKey                  :
        LocationOfAESKey                   :
        AllFileOutputs                     :
        DecryptedContent                   : {fruit, vegetables, meat}

    .EXAMPLE
        # Decrypting a File
        PS C:\Users\zeroadmin> Decrypt-EncryptedFile -ContentType File -ContentToDecrypt C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted -CNofCertInStore TempDirEncryption -AESKeyLocation C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
        Doing AES Decryption


        DecryptedFiles                     : C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted
        FailedToDecryptFiles               : {}
        CertUsedDuringDecryption           : [Subject]
                                            CN=TempDirEncryption

                                            [Issuer]
                                            CN=TempDirEncryption

                                            [Serial Number]
                                            52711274E381F592437E8C18C7A3241C

                                            [Not Before]
                                            6/2/2017 10:57:26 AM

                                            [Not After]
                                            6/2/2018 11:17:26 AM

                                            [Thumbprint]
                                            F2EFEBB37C37844A230961447C7C91C1DE13F1A5

        PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\tempdir\PrivateKeyExtractionTempDir\TempDirEncryption.pfx
        LocationOfCertUsedDuringDecryption : Cert:\LocalMachine\My
        UnprotectedAESKey                  : BKcLSwqZjSq/D1RuqBGBxZ0dng+B3JwrWJVlhqgxrmo=
        LocationOfAESKey                   : C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
        AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted,
                                            C:\Users\zeroadmin\tempdir\PrivateKeyExtractionTempDir\TempDirEncryption.pfx}
        DecryptedContent                   : {1914 translation by H. Rackham, , "But I must explain to you how all this mistaken idea of denouncing pleasure and
                                            praising pain was born and I will give you a complete account of the system, and expound the actual teachings of the
                                            great explorer of the truth, the master-builder of human happiness. No one rejects, dislikes, or avoids pleasure itself,
                                            because it is pleasure, but because those who do not know how to pursue pleasure rationally encounter consequences that
                                            are extremely painful. Nor again is there anyone who loves or pursues or desires to obtain pain of itself, because it is
                                            pain, but because occasionally circumstances occur in which toil and pain can procure him some great pleasure. To take a
                                            trivial example, which of us ever undertakes laborious physical exercise, except to obtain some advantage from it? But
                                            who has any right to find fault with a man who chooses to enjoy a pleasure that has no annoying consequences, or one who
                                            avoids a pain that produces no resultant pleasure?", ...}

    .EXAMPLE
        # Decrypting All Files in a Directory
        PS C:\Users\zeroadmin> Decrypt-EncryptedFile -ContentType Directory -ContentToDecrypt C:\Users\zeroadmin\tempdir -Recurse -CNofCertInStore TempDirEncryption -AESKeyLocation C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
        Doing AES Decryption
        WARNING: Unable to read IV from C:\Users\zeroadmin\tempdir\dolor.txt.original, verify this file was made using the included EncryptFile function.
        WARNING: AES Decryption of C:\Users\zeroadmin\tempdir\dolor.txt.original failed...Will try RSA Decryption...
        WARNING: Unable to read IV from C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted, verify this file was made using the included EncryptFile function.
        WARNING: AES Decryption of C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted failed...Will try RSA Decryption...
        WARNING: Unable to read IV from C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.original, verify this file was made using the included EncryptFile function.
        WARNING: AES Decryption of C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.original failed...Will try RSA Decryption...


        DecryptedFiles                     : {C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted,
                                            C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.aesencrypted.decrypted,
                                            C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted.decrypted}
        FailedToDecryptFiles               : {C:\Users\zeroadmin\tempdir\dolor.txt.original, C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.original}
        CertUsedDuringDecryption           : [Subject]
                                            CN=TempDirEncryption

                                            [Issuer]
                                            CN=TempDirEncryption

                                            [Serial Number]
                                            52711274E381F592437E8C18C7A3241C

                                            [Not Before]
                                            6/2/2017 10:57:26 AM

                                            [Not After]
                                            6/2/2018 11:17:26 AM

                                            [Thumbprint]
                                            F2EFEBB37C37844A230961447C7C91C1DE13F1A5

        PFXCertUsedForPrivateKeyExtraction : C:\Users\zeroadmin\PrivateKeyExtractionTempDir\TempDirEncryption.pfx
        LocationOfCertUsedDuringDecryption : Cert:\LocalMachine\My
        UnprotectedAESKey                  : BKcLSwqZjSq/D1RuqBGBxZ0dng+B3JwrWJVlhqgxrmo=
        LocationOfAESKey                   : C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
        AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted.decrypted,
                                            C:\Users\zeroadmin\tempdir\tempdir1\agricola.txt.aesencrypted.decrypted,
                                            C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted.decrypted,
                                            C:\Users\zeroadmin\PrivateKeyExtractionTempDir\TempDirEncryption.pfx}
        DecryptedContent                   : {1914 translation by H. Rackham, , "But I must explain to you how all this mistaken idea of denouncing pleasure and
                                            praising pain was born and I will give you a complete account of the system, and expound the actual teachings of the
                                            great explorer of the truth, the master-builder of human happiness. No one rejects, dislikes, or avoids pleasure itself,
                                            because it is pleasure, but because those who do not know how to pursue pleasure rationally encounter consequences that
                                            are extremely painful. Nor again is there anyone who loves or pursues or desires to obtain pain of itself, because it is
                                            pain, but because occasionally circumstances occur in which toil and pain can procure him some great pleasure. To take a
                                            trivial example, which of us ever undertakes laborious physical exercise, except to obtain some advantage from it? But
                                            who has any right to find fault with a man who chooses to enjoy a pleasure that has no annoying consequences, or one who
                                            avoids a pain that produces no resultant pleasure?", ...}
#>
function Decrypt-EncryptedFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet("String","ArrayOfStrings","File","Directory")]
        $ContentType,

        [Parameter(Mandatory=$True)]
        $ContentToDecrypt,

        [Parameter(Mandatory=$False)]
        [switch]$Recurse,

        [Parameter(Mandatory=$False)]
        $FileToOutput,
        
        [Parameter(Mandatory=$False)]
        $PathToCertFile,

        [Parameter(Mandatory=$False)]
        $CNofCertInStore,

        [Parameter(Mandatory=$False)]
        [securestring]$CertPwd,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AES","RSA")]
        $TypeOfEncryptionUsed,

        [Parameter(Mandatory=$False)]
        $AESKey,

        [Parameter(Mandatory=$False)]
        $AESKeyLocation,

        [Parameter(Mandatory=$False)]
        [switch]$NoFileOutput
    )

    ##### BEGIN Parameter Validation #####

    if ($ContentToDecrypt.GetType().Fullname -eq "System.String" -and !$ContentType) {
        $ContentType = "String"
    }
    if ($ContentToDecrypt.GetType().Fullname -match "System.String\[\]|System.Object\[\]" -and !$ContentType) {
        $ContentType = "ArrayOfStrings"
    }

    if ($ContentType -match "String|ArrayOfStrings" -and !$FileToOutput) {
        if (!$NoFileOutput) {
            $FileToOutput = Read-Host -Prompt "Please enter the full path to the New File that will contain the Decrypted string."
        }
        if ($NoFileOutput) {
            $FileToOutput = $(Get-Location).Path
        }
    }
    if ($ContentType -match "String|ArrayOfStrings" -and !$ContentToDecrypt) {
        $ContentToDecrypt = Read-Host -Prompt "Please enter the string that you would like to Decrypt and output to $FileToOutput"
    }
    if ($ContentType -eq "File" -and $FileToOutput) {
        Write-Verbose "The -FileToOutput should NOT be used when -ContentType is `"File`". Simply use `"-ContentType File`" and output file naming convention will be handled automatically by the Decrypt-EncryptedFile function. Halting!"
        Write-Error "The -FileToOutput should NOT be used when -ContentType is `"File`". Simply use `"-ContentType File`" and output file naming convention will be handled automatically by the Decrypt-EncryptedFile function. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory" -and $FileToOutput) {
        Write-Verbose "The -FileToOutput should NOT be used when -ContentType is `"Directory`". Simply using `"-ContentType Directory`" will create new decrypted files in the specified Directory. Halting!"
        Write-Error "The -FileToOutput should NOT be used when -ContentType is `"Directory`". Simply using `"-ContentType Directory`" will create new decrypted files in the specified Directory. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($Recurse -and $ContentType -ne "Directory") {
        Write-Verbose "The -Recurse switch should only be used when -ContentType is `"Directory`"! Halting!"
        Write-Error "The -Recurse switch should only be used when -ContentType is `"Directory`"! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($ContentType -eq "String" -and $ContentToDecrypt.GetType().FullName -ne "System.String") {
        Write-Verbose "ContentType 'String' was specified but the object passed to ContentToEncrypt is $($ContentToDecrypt.GetType().FullName). Halting!"
        Write-Error "ContentType 'String' was specified but the object passed to ContentToEncrypt is $($ContentToDecrypt.GetType().FullName). Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "ArrayofStrings" -and $ContentToDecrypt.GetType().FullName -notmatch "System.String\[\]|System.Object\[\]") {
        Write-Verbose "ContentType 'ArrayOfStrings' was specified but the object passed to ContentToEncrypt is $($ContentToDecrypt.GetType().FullName). Halting!"
        Write-Error "ContentType 'ArrayOfStrings' was specified but the object passed to ContentToEncrypt is $($ContentToDecrypt.GetType().FullName). Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "ArrayofStrings" -and $ContentToDecrypt.GetType().FullName -match "System.Object\[\]") {
        $InspectArrayObjects = $(foreach ($obj in $ContentToDecrypt) {
            $obj.GetType().FullName
        }) | Sort-Object | Get-Unique
        if ($InspectArrayObjects -ne "System.String") {
            Write-Verbose "Not all array elements in -ContentToEncrypt are of type System.String! Halting!"
            Write-Error "Not all array elements in -ContentToEncrypt are of type System.String! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($ContentType -eq "File" -and !$(Test-Path $ContentToDecrypt)) {
        Write-Verbose "The path $ContentToDecrypt was not found! Halting!"
        Write-Error "The path $ContentToDecrypt was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory" -and !$(Test-Path $ContentToDecrypt)) {
        Write-Verbose "The path $ContentToDecrypt was not found! Halting!"
        Write-Error "The path $ContentToDecrypt was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory") {
        if ($Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem -Recurse $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}
        }
        if (!$Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}
        }
        if ($PossibleFilesToEncrypt.Count -lt 1) {
            Write-Verbose "No files were found in the directory $ContentToDecrypt. Halting!"
            Write-Error "No files were found in the directory $ContentToDecrypt. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($FileToOutput) {
        $position = $FileToOutput.LastIndexOf("\")
        $FileToOutputDirectory = $FileToOutput.Substring(0, $position)
        $FileToOutputFile = $FileToOutput.Substring($position+1)
        $FileToOutputFileSansExt = $($FileToOutputFile.Split("."))[0]
        if (! $(Test-Path $FileToOutputDirectory)) {
            Write-Host "The directory $FileToOutputDirectory does not exist. Please check the path."
            $FileToOutput = Read-Host -Prompt "Please enter the full path to the output file that will be created"
            if (! $(Test-Path $FileToOutputDirectory)) {
                Write-Error "The directory $FileToOutputDirectory does not exist. Please check the path. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }


    # Gather the Cert Used For RSA Decryption and the AES Key (if necessary)
    if ($PathToCertFile -ne $null -and $CNofCertInStore -ne $null) {
        Write-Host "Please use *either* a .pfx certificate file *or*  a certificate in the user's local certificate store to decrypt the password file"
        $WhichCertSwitch = Read-Host -Prompt "Would you like to use the certificate file or the certificate in the local user's cert store? [File/Store]"
        if ($WhichCertSwitch -eq "File" -or $WhichCertSwitch -eq "Store") {
            Write-Host "Continuing..."
        }
        else {
            Write-Host "The string entered did not match either 'File' or 'Store'. Please type either 'File' or 'Store'"
            $WhichCertSwitch = Read-Host -Prompt "Would you like to use the certificate file or the certificate in the local user's cert store? [File/Store]"
            if ($WhichCertSwitch -eq "File" -or $WhichCertSwitch -eq "Store") {
                Write-Host "Continuing..."
            }
            else {
                Write-Error "The string entered did not match either 'File' or 'Store'. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($WhichCertSwitch -eq "File") {
            Remove-Variable -Name "PathToCertInStore" -Force -ErrorAction SilentlyContinue
        }
        if ($WhichCertSwitch -eq "Store") {
            Remove-Variable -Name "PathToCertFile" -Force -ErrorAction SilentlyContinue
        }
    }

    if ($PathToCertFile -eq $null -and $CNofCertInStore -eq $null) {
        $FileOrStoreSwitch = Read-Host -Prompt "Would you like to use a certificate File in .pfx format, or a Certificate that has already been loaded in the certificate Store in order to decrypt the file? [File/Store]"
        if ($FileOrStoreSwitch -eq "File" -or $FileOrStoreSwitch -eq "Store") {
            Write-Host "Continuing..."
        }
        else {
            Write-Host "The string entered did not match either 'File' or 'Store'. Please type either 'File' or 'Store'"
            $FileOrStoreSwitch = Read-Host -Prompt "Would you like to use a certificate File in .pfx format, or a Certificate that has already been loaded in the certificate Store? [File,Store]"
            if ($FileOrStoreSwitch -eq "File" -or $FileOrStoreSwitch -eq "Store") {
                Write-Host "Continuing..."
            }
            else {
                Write-Error "The string entered did not match either 'File' or 'Store'. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    # Validate PathToCertFile
    if ($PathToCertFile -or $FileOrStoreSwitch -eq "File") { 
        if ($FileOrStoreSwitch -eq "File") {
            $PathToCertFile = Read-Host -Prompt "Please enter the full path to the .pfx certificate file."
        }
        if (!$(Test-Path $PathToCertFile)) {
            Write-Host "The $PathToCertFile was not found. Please check to make sure the file exists."
            $PathToCertFile = Read-Host -Prompt "Please enter the full path to the .pfx certificate file. Example: C:\ps_scripting.pfx"
            if (!$(Test-Path $PathToCertFile)) {
                Write-Error "The .pfx certificate file was not found at the path specified. Halting."
                $global:FunctionResult = "1"
                return
            }
        }

        # See if Cert is password protected
        try {
            # First, try null password
            $Cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToCertFile, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        }
        catch {
            Write-Host "Either the Private Key is Password Protected, or it is marked as Unexportable..."
            if (!$CertPwd) {
                $CertPwd = Read-Host -Prompt "Please enter the password for the certificate $($TestCertObj.Subject). If there is no password, simply press [ENTER]" -AsSecureString
            }

            # Next, try $CertPwd 
            try {
                $Cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToCertFile, $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            }
            catch {
                Write-Warning "Incorrect certificate password"
                $CertPwdFailure = $true
            }
        }
        if ($CertPwdFailure) {
            Write-Verbose "The password supplied for certificate is incorrect! Halting!"
            Write-Error "The password supplied for certificate is incorrect! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    
    # Validate CNofCertInStore {
    if ($CNofCertInStore -or $FileOrStoreSwitch -eq "Store") {
        if ($FileOrStoreSwitch -eq "Store") {
            $CNofCertInStore = Read-Host -Prompt "Please enter the CN of the Certificate you would like to use to decrypt the password file"
        }
        $Cert2 = $(Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=$CNofCertInStore"})

        if ($Cert2.Count -gt 1) {
            Write-Host "More than one Certificate with a CN beginning with CN=$CNofCertInStore has been identified. Only one Certificate may be used. 
            A list of available Certificates in the User Store are as follows:"
            foreach ($obj1 in $(Get-ChildItem "Cert:\LocalMachine\My").Subject) {$obj1.Split(",")[0]}
            $CNofCertInStore = Read-Host -Prompt "Please enter the CN of the Certificate you would like to use to decrypt the password file"
            $Cert2 = $(Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=$CNofCertInStore"})
            if ($PathToCertInStore.Count -gt 1) {
                Write-Error "More than one Certificate with a CN beginning with CN=$CNofCertInStore has been identified. Only one Certificate may be used. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
    }

    # Make sure we have the Private Key
    if ($Cert2.PrivateKey -eq $null -and $Cert2.HasPrivateKey -eq $true) {
        if (! $(Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
            Write-Warning "Windows reports that the certificate being used for decryption has a Private Key (which is necessary for decryption), but the Private Key information is not readily available."
            $UseOpenSSLQuery = Read-Host -Prompt "Do you want to download OpenSSL to $HOME\Downloads and add it to your `$env:Path? [Yes\No]"
            if ($UseOpenSSLQuery -match "Y|y|Yes|yes") {
                try {
                    $ContentToDecryptParentDirTest = $ContentToDecrypt | Split-Path -Parent
                    $TempOutputDirPrep = $(Resolve-Path $ContentToDecryptParentDirTest -ErrorAction SilentlyContinue).Path
                    if (!$TempOutputDirPrep) {
                        throw
                    }

                    New-Item -Type Directory -Path "$TempOutputDirPrep\PrivateKeyExtractionTempDir" | Out-Null
                    $TempOutputDir = "$TempOutputDirPrep\PrivateKeyExtractionTempDir"
                }
                catch {
                    if ($NoFileOutput) {
                        $TempOutputDirPrep = $(Get-Location).Path
                    }
                    else {
                        $TempOutputDirPrep = $FileToOutput | Split-Path -Parent
                    }

                    New-Item -Type Directory -Path "$TempOutputDirPrep\PrivateKeyExtractionTempDir" | Out-Null
                    $TempOutputDir = "$TempOutputDirPrep\PrivateKeyExtractionTempDir"
                }
                if ($CertPwd) {
                    $PrivateKeyInfo = Get-PrivateKeyProperty -CertObject $Cert2 -TempOutputDirectory $TempOutputDir -CertPwd $CertPwd -DownloadAndAddOpenSSLToPath
                }
                else {
                    $PrivateKeyInfo = Get-PrivateKeyProperty -CertObject $Cert2 -TempOutputDirectory $TempOutputDir -DownloadAndAddOpenSSLToPath
                }
            }
            else {
                Write-Verbose "Unable to get Private Key Info without openssl and therefore unable to decrypt $ContentToDecrypt! Halting!"
                Write-Error "Unable to get Private Key Info without openssl and therefore unable to decrypt $ContentToDecrypt! Halting!"
                $FunctionResult = "1"
                return
            }
        }
        else {
            try {
                $ContentToDecryptParentDirTest = $ContentToDecrypt | Split-Path -Parent
                $TempOutputDirPrep = $(Resolve-Path $ContentToDecryptParentDirTest -ErrorAction SilentlyContinue).Path
                if (!$TempOutputDirPrep) {
                    throw
                }

                New-Item -Type Directory -Path "$TempOutputDirPrep\PrivateKeyExtractionTempDir" | Out-Null
                $TempOutputDir = "$TempOutputDirPrep\PrivateKeyExtractionTempDir"
            }
            catch {
                if ($NoFileOutput) {
                    $TempOutputDirPrep = $(Get-Location).Path
                }
                else {
                    if ($FileToOutput) {
                        $TempOutputDirPrep = $FileToOutput | Split-Path -Parent
                    }
                }

                New-Item -Type Directory -Path "$TempOutputDirPrep\PrivateKeyExtractionTempDir" | Out-Null
                $TempOutputDir = "$TempOutputDirPrep\PrivateKeyExtractionTempDir"
            }
            if ($CertPwd) {
                $PrivateKeyInfo = Get-PrivateKeyProperty -CertObject $Cert2 -TempOutputDirectory $TempOutputDir -CertPwd $CertPwd
            }
            else {
                $PrivateKeyInfo = Get-PrivateKeyProperty -CertObject $Cert2 -TempOutputDirectory $TempOutputDir
            }
        }
        if ($PrivateKeyInfo.KeySize -eq $null) {
            Write-Verbose "Openssl failed to get Private Key Info from $($Cert2.Subject) ! Halting!"
            Write-Error "Failed to get Private Key Info from $($Cert2.Subject) ! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($Cert2.PrivateKey -eq $null -and $Cert2.HasPrivateKey -eq $false) {
        Write-Verbose "There is no private key available for the certificate $($Cert2.Subject)! We need the private key to decrypt the file! Halting!"
        Write-Error "There is no private key available for the certificate $($Cert2.Subject)! We need the private key to decrypt the file! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Figure out if we need an AES key. If so, get it.
    if ($TypeOfEncryptionUsed -eq "AES" -or $ContentToDecrypt -match "\.aesencrypted" -or $AESKey -or $AESKeyLocation) {
        $NeedAES = $true
    }
    if ($ContentType -eq "Directory" -and $TypeOfEncryptionUsed -ne "RSA") {
        # Default to $NeedAES since the Decryption Code Block where ContentType is "Directory" can handle both AES and RSA
        # by first trying AES Decryption, and if that fails, trying RSA Decryption
        $NeedAES = $true
    }
    if ($NeedAES) {
        if (!$AESKey -and !$AESKeyLocation) {
            $AESKeyLocation = Read-Host -Prompt "Please enter the full path to the file that contains the AES Key used to originally encrypt $ContentToDecrypt"
        }
        if (!$AESKey -and $AESKeyLocation) {
            if (!$(Test-Path $AESKeyLocation)) {
                Write-Verbose "The path $AESKeyLocation was not found! Halting!"
                Write-Error "The path $AESKeyLocation was not found! Halting!"
                $global:FunctionResult = "1"
                return
            }
            if ($(Get-ChildItem $AESKeyLocation).Extension -eq ".rsaencrypted") {
                $EncryptedBase64String = Get-Content $AESKeyLocation
                $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedBase64String)
                #$EncryptedBytes2 = [System.IO.File]::ReadAllBytes($AESKeyLocation)
                if ($PrivateKeyInfo) {
                    #$DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                    $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                }
                else {
                    #$DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                    $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                }
                #$AESKey = [System.Convert]::ToBase64String($DecryptedBytes2)
                $DecryptedContent2 = [system.text.encoding]::Unicode.GetString($DecryptedBytes2)
                #$DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                # Need to write $DecryptedContent2 to tempfile to strip BOM if present
                $tmpFile = [IO.Path]::GetTempFileName()
                [System.IO.File]::WriteAllLines($tmpFile, $DecryptedContent2.Trim())
                $AESKey = Get-Content $tmpFile
                Remove-Item $tmpFile -Force
            }
            # If the $AESKeyLocation file extension is not .rsaencrypted, assume it's the unprotected AESKey
            if ($(Get-ChildItem $AESKeyLocation).Extension -ne ".rsaencrypted"){
                $AESKey = Get-Content $AESKeyLocation
            }
        }
    }

    ##### END Parameter Validation #####

    ##### BEGIN Main Body #####

    $DecryptedFiles = @()
    $FailedToDecryptFiles = @()
    $TryRSADecryption = @()
    # Do RSA Decryption on $ContentToDecrypt
    if ($TypeOfEncryptionUsed -eq "RSA"-or !$NeedAES) {
        Write-Host "Doing RSA Decryption"
        if ($ContentType -eq "String" -or $ContentType -eq "File") {
            if ($ContentType -eq "String") {
                $EncryptedString2 = $ContentToDecrypt
                $OutputFile = "$FileToOutput.decrypted"
            }
            if ($ContentType -eq "File") {
                $EncryptedString2 = Get-Content $ContentToDecrypt
                $OutputFile = "$ContentToDecrypt.decrypted"
            }

            try {
                $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedString2)
                if ($PrivateKeyInfo) {
                    #$DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                    $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                }
                else {
                    #$DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                    $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                }
                $DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                $DecryptedContent2 = $DecryptedContent2.Trim()
                # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)

                $DecryptedFiles += $OutputFile
            }
            catch {
                Write-Error $_
                $FailedToDecryptFiles += $Outputfile
            }
        }
        if ($ContentType -eq "ArrayOfStrings") {
            $ArrayOfEncryptedStrings = $ContentToDecrypt

            for ($i=0; $i -lt $ArrayOfEncryptedStrings.Count; $i++) {
                $OutputFile = "$FileToOutput$i.decrypted"
                try {
                    $EncryptedBytes2 = [System.Convert]::FromBase64String($ArrayOfEncryptedStrings[$i])
                    if ($PrivateKeyInfo) {
                        #$DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                    }
                    else {
                        #$DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                    }
                    $DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                    $DecryptedContent2 = $DecryptedContent2.Trim()
                    # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                    [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)

                    $DecryptedFiles += $OutputFile
                }
                catch {
                    Write-Error $_
                    $FailedToDecryptFiles += $Outputfile
                }
            }
        }
        if ($ContentType -eq "Directory") {
            if ($Recurse) {
                $DecryptionCandidates = $(Get-ChildItem -Recurse $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
            }
            if (!$Recurse) {
                $DecryptionCandidates = $(Get-ChildItem $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
            }

            foreach ($file in $DecryptionCandidates) {
                $EncryptedString2 = Get-Content $file
                $OutputFile = "$file.decrypted"

                try {
                    $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedString2)
                    if ($PrivateKeyInfo) {
                        #$DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                    }
                    else {
                        #$DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                    }
                    $DecryptedContent2 = [system.text.encoding]::UTF8.GetString($DecryptedBytes2)
                    $DecryptedContent2 = $DecryptedContent2.Trim()
                    # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                    [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)

                    $DecryptedFiles += $OutputFile
                }
                catch {
                    Write-Error $_
                    $FailedToDecryptFiles += $Outputfile
                }
            }
        }
    }
    # Do AES Decryption on $ContentToDecrypt
    if ($TypeOfEncryptionUsed -eq "AES" -or $NeedAES) {
        Write-Host "Doing AES Decryption"
        if ($ContentType -eq "String" -or $ContentType -eq "File") {
            if ($ContentType -eq "String") {
                # Temporarily write the string to a file
                $tmpFile = [IO.Path]::GetTempFileName()
                $tmpFileRenamed = "$tmpFile.aesencrypted"
                [System.IO.File]::WriteAllLines($tmpfileRenamed, $ContentToDecrypt)

                try {
                    $FileDecryptionInfo = DecryptFile $tmpFileRenamed -Key $AESKey
                    # Now we're left with a file $tmpFile containing decrypted info. Copy it to $FileToOutput
                    Move-Item -Path $tmpFile -Destination $FileToOutput

                    $DecryptedFiles += $FileToOutput
                }
                catch {
                    Write-Error $_
                    $FailedToDecryptFiles += $FileToOutput
                }
            }
            if ($ContentType -eq "File") {
                <#
                if ($(Get-ChildItem $ContentToDecrypt).Extension -ne ".aesencrypted") {
                    Rename-Item -Path $ContentToDecrypt -NewName "$ContentToDecrypt.aesencrypted"
                    $UpdatedContentToDecrypt = "$ContentToDecrypt.aesencrypted"
                }
                else {
                    $UpdatedContentToDecrypt = $ContentToDecrypt
                }
                #>

                try {
                    $FileDecryptionInfo = DecryptFile $ContentToDecrypt -Key $AESKey
                    $DecryptedFiles += "$ContentToDecrypt.decrypted"
                }
                catch {
                    Write-Error $_
                    $FailedToDecryptFiles += $ContentToDecrypt
                }
                
            }
        }
        if ($ContentType -eq "ArrayOfStrings") {
            $ArrayOfEncryptedStrings = $ContentToDecrypt

            for ($i=0; $i -lt $ArrayOfEncryptedStrings.Count; $i++) {
                $OutputFile = "$FileToOutput$i"

                # Temporarily write the string to a file
                $tmpFile = [IO.Path]::GetTempFileName()
                $tmpFileRenamed = "$tmpFile.aesencrypted"
                [System.IO.File]::WriteAllLines($tmpfileRenamed, $ArrayOfEncryptedStrings[$i])

                try {
                    $FileDecryptionInfo = DecryptFile $tmpFileRenamed -Key $AESKey
                    # Now we're left with a file $tmpFile containing decrypted info. Copy it to $FileToOutput
                    Move-Item -Path $tmpFile -Destination $OutputFile

                    $DecryptedFiles += $OutputFile
                }
                catch {
                    Write-Error $_
                    $FailedToDecryptFiles += $OutputFile
                }
            }
        }
        if ($ContentType -eq "Directory") {
            if ($Recurse) {
                $DecryptionCandidates = $(Get-ChildItem -Recurse $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
            }
            if (!$Recurse) {
                $DecryptionCandidates = $(Get-ChildItem $ContentToDecrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
            }

            foreach ($file in $DecryptionCandidates) {
                $FileExtenstion = $(Get-ChildItem $file).Extension
                if ($FileExtension -eq ".aesencrypted" -or $TypeOfEncryptionUsed -eq "AES" -or !$TypeOfEncryptionUsed) {
                    #Rename-Item -Path $file -NewName "$($(Get-ChildItem $file).Name).aesencrypted"
                    #$UpdatedContentToDecrypt = "$file.aesencrypted"

                    try {
                        $FileDecryptionInfo = DecryptFile $file -Key $AESKey
                        if ($($FileDecryptionInfo.FilesFailedToDecrypt).Count -gt 0) {
                            $TryRSADecryption += $($FileDecryptionInfo.FilesFailedToDecrypt).FullName
                            throw
                        }

                        $DecryptedFiles += "$file.decrypted"
                    }
                    catch {
                        $AESDecryptionFailed = $true
                        Write-Warning "AES Decryption of $file failed...Will try RSA Decryption..."
                    }
                }
            }
            foreach ($file in $TryRSADecryption) {
                $EncryptedString2 = Get-Content $file
                $OutputFile = "$file.decrypted"

                try {
                    $EncryptedBytes2 = [System.Convert]::FromBase64String($EncryptedString2)
                    if ($PrivateKeyInfo) {
                        #$DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $PrivateKeyInfo.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                    }
                    else {
                        #$DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, $true)
                        $DecryptedBytes2 = $Cert2.PrivateKey.Decrypt($EncryptedBytes2, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
                    }
                    $DecryptedContent2 = [system.text.encoding]::Unicode.GetString($DecryptedBytes2)
                    $DecryptedContent2 = $DecryptedContent2.Trim()
                    # Need to write $DecryptedContent2 using [System.IO.File]::WriteAllLines() to strip BOM if present
                    [System.IO.File]::WriteAllLines("$OutputFile", $DecryptedContent2)

                    $DecryptedFiles += $OutputFile
                }
                catch {
                    #Write-Error $_
                    $FailedToDecryptFiles += $(Get-ChildItem $file).FullName
                }
            }
        }
    }

    # Output
    if ($PrivateKeyInfo) {
        $CertName = $($Cert2.Subject | Select-String -Pattern "^CN=[\w]+").Matches.Value -replace "CN=",""
        $PFXCertUsedForPrivateKeyExtraction = "$TempOutputDir\$CertName.pfx"
    }

    $AllFileOutputsPrep = $DecryptedFiles,$PFXCertUsedForPrivateKeyExtraction
    $AllFileOutputs = foreach ($element in $AllFileOutputsPrep) {if ($element -ne $null) {$element}}


    New-Variable -Name "Output" -Value $(
        [pscustomobject][ordered]@{
            DecryptedFiles                          = $(if ($NoFileOutput) {$null} else {$DecryptedFiles})
            FailedToDecryptFiles                    = $FailedToDecryptFiles
            CertUsedDuringDecryption                = $Cert2
            PFXCertUsedForPrivateKeyExtraction      = $PFXCertUsedForPrivateKeyExtraction
            LocationOfCertUsedDuringDecryption      = $(if ($PathToCertFile) {$PathToCertFile} else {"Cert:\LocalMachine\My"})
            UnprotectedAESKey                       = $AESKey
            LocationOfAESKey                        = $AESKeyLocation
            AllFileOutputs                          = $(if ($NoFileOutput) {$null} else {$AllFileOutputs})
            DecryptedContent                        = $(foreach ($file in $DecryptedFiles) {Get-Content $file})
        }
    )
    
    $Output

    # Cleanup
    if ($NoFileOutput) {
        foreach ($item in $DecryptedFiles) {
            Remove-Item $item -Force
        }
        if ($TempOutputDir) {
            Remove-Item -Recurse $TempOutputDir -Force
        }
    }

    ##### END Main Body #####
    $global:FunctionResult = "0"
}