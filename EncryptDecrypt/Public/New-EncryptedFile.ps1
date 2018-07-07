<#
    .SYNOPSIS
        This function can encrypt a String, Array of Strings, File, or Files in a Directory. Strings and Arrays of Strings passed
        to the -ContentToEncrypt parameter are written to their own separate encrypted files on the file system. Encrypting one or
        more Files creates a NEW encrypted version of the original File(s). It DOES NOT TOUCH the original unencrypted File(s).

    .DESCRIPTION
        See SYNOPSIS.

    .NOTES
        Please use this function responsibly.

        IMPORTANT NOTE #1:
        The Certificate used for RSA Encryption is written out (in .pfx format) to the same directory as the encrypted
        file outputs. If AES encryption is needed for larger Files, the RSA-encrypted AES Key is written to the same directory
        as the encrypted file outputs.

        You will ALWAYS need a private key from your Certificate's public/private pair in order to decrypt content
        encrypted via this function. You will be able to get this private key from the .pfx file that you provide
        to the -PathToCertFile parameter, or from the Certificate in the Cert:\LocalMachine\My store that you provide
        to the -CNofCertInStore parameter of this function.

        You will SOMETIMES need the AES Key to decrypt larger files that were encrypted using AES encryption.

        IMPORTANT NOTE #2:
        It is up to you to store the public/private key pair and the RSA-encrypted AES Key appropriately.

        Note that the public/private key pair will be found EITHER in a .pfx file in the same directory as encrypted
        file outputs OR in Cert:\LocalMachine\My OR in BOTH locations. Note that the RSA-encrypted AES Key will be
        found in a file in the same directory as encrypted file outputs.

    .PARAMETER ContentType
        Optional, but HIGHLY recommended.

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
        encrypted.

        If this switch IS used, all files immediately under the directory specified by -ContentToEncrypt AS WELL AS
        all files within subdirectories under the directory specified by -ContentToEncrypt are encrypted.

    .PARAMETER FileToOutput
        Optional.

        This parameter specifies a full path to a NEW file that will contain encrypted information. This parameter should
        ONLY be used if -ContentType is "String" or "ArrayOfStrings". If this parameter is used and -ContentType is NOT
        "String" or "ArrayOfStrings", the function will immediately fail.

    .PARAMETER PathToCertFile
        Optional.

        This parameter takes a string that represents the full path to a .pfx file. The public certificate in the
        .pfx file will be used for RSA encryption.

        NOTE: RSA encryption is ALWAYS used by this function, either to encrypt the information directly or to encrypt the
        AES Key that was used to encrypt the information.

    .PARAMETER CNOfCertInStore
        Optional.

        This parameter takes a string that represents the Common Name (CN) of the public certificate used for RSA
        encryption. This certificate must already exist in the Local Machine Store (i.e. Cert:\LocalMachine\My).

        NOTE: RSA encryption is ALWAYS used by this function, either to encrypt the information directly or to encrypt the
        AES Key that was used to encrypt the information.

    .PARAMETER CertPwd
        Optional. (However, this parameter is mandatory if the certificate is password protected).

        This parameter takes a System.Security.SecureString that represents the password for the certificate.

        Use this parameter if the certificate is password protected.

    .EXAMPLE
        # String Encryption Example
        # NOTE: If neither -PathToCertFile nor -CNOfCertInStore parameters are used, a NEW Self-Signed Certificate is
        # created and added to Cert:\LocalMachine\My

        PS C:\Users\zeroadmin> New-EncryptedFile -ContentType "String" -ContentToEncrypt "MyPLaInTeXTPwd321!" -FileToOutput $HOME\MyPwd.txt

        FileEncryptedViaRSA                : C:\Users\zeroadmin\MyPwd.txt.rsaencrypted
        FileEncryptedViaAES                :
        OriginalFile                       :
        CertficateUsedForRSAEncryption     : [Subject]
                                            CN=MyPwd

                                            [Issuer]
                                            CN=MyPwd

                                            [Serial Number]
                                            6BD1BF9FACE6F0BB4EFFC31597E9B970

                                            [Not Before]
                                            6/2/2017 10:39:31 AM

                                            [Not After]
                                            6/2/2018 10:59:31 AM

                                            [Thumbprint]
                                            34F3526E85C04CEDC79F26C2B086E52CF75F91C3

        LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My
        UnprotectedAESKey                  :
        RSAEncryptedAESKey                 :
        RSAEncryptedAESKeyLocation         :
        AllFileOutputs                     : C:\Users\zeroadmin\MyPwd.txt.rsaencrypted 

    .EXAMPLE
        # ArrayOfStrings Encryption Example
        PS C:\Users\zeroadmin> $foodarray = @("fruit","vegetables","meat")
        PS C:\Users\zeroadmin> New-EncryptedFile -ContentType ArrayOfStrings -ContentToEncrypt $foodarray -PathToCertFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -FileToOutput $HOME\Food.txt

        FilesEncryptedViaRSA               : {C:\Users\zeroadmin\Food.txt0.rsaencrypted, C:\Users\zeroadmin\Food.txt1.rsaencrypted,
                                            C:\Users\zeroadmin\Food.txt2.rsaencrypted}
        FilesEncryptedViaAES               :
        OriginalFiles                      :
        CertficateUsedForRSAEncryption     : [Subject]
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

        LocationOfCertUsedForRSAEncryption : C:\Users\zeroadmin\other\ArrayOfStrings.pfx
        UnprotectedAESKey                  :
        RSAEncryptedAESKey                 :
        RSAEncryptedAESKeyLocation         :
        AllFileOutputs                     : {C:\Users\zeroadmin\Food.txt0.rsaencrypted, C:\Users\zeroadmin\Food.txt1.rsaencrypted,
                                            C:\Users\zeroadmin\Food.txt2.rsaencrypted}

    .EXAMPLE
        # File Encryption Example
        PS C:\Users\zeroadmin> $ZeroTestPwd = Read-Host -Prompt "Enter password for ZeroTest Cert" -AsSecureString
        Enter password for ZeroTest Cert: ***********************
        PS C:\Users\zeroadmin> New-EncryptedFile -ContentType File -ContentToEncrypt C:\Users\zeroadmin\tempdir\lorumipsum.txt -CNofCertInStore "ZeroTest" -CertPwd $ZeroTestPwd

        FileEncryptedViaRSA                :
        FileEncryptedViaAES                : C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted
        OriginalFile                       : C:\Users\zeroadmin\tempdir\lorumipsum.txt.original
        CertficateUsedForRSAEncryption     : [Subject]
                                            CN=ZeroTesting.zero.lab

                                            [Issuer]
                                            <redacted>

                                            [Serial Number]
                                            <redacted>

                                            [Not Before]
                                            <redacted>

                                            [Not After]
                                            <redacted>

                                            [Thumbprint]
                                            <redacted>

        LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My
        UnprotectedAESKey                  : E0588dE3siWEOAyM7A5+6LKqC5tG1egxXTfsUUE5sNM=
        RSAEncryptedAESKey                 : NkKjOwd8T45u1Hpn0CL9m5zD/97PG9GNnJCShh0vOUTn+m+E2nLFxuW7ChKiHCVtP1vD2z+ckW3kk1va3PAfjw3/hfm9zi2qn4Xu7kPdWL1owDdQyvBuUPTc35
                                            FSqaIJxxdsqWLnUHo1PINY+2usIPT5tf57TbTKbAg5q/RXOzCeUS+QQ+nOKMgQGnadlUVyyIYo2JRdzzKaTSHRwK4QFdDk/PUy39ei2FVOIlwitiAkWTyjFAb6
                                            x+kMCgOVDuALGOyVVBdNe+BDrrWgqnfRSCHSZoQKfnkA0dj0tuE2coYNwGQ6SVUmiDrdklBrnKl69cIFf8lkTSsUqGdq9bbaag==
        RSAEncryptedAESKeyLocation         : C:\Users\zeroadmin\tempdir\lorumipsum.aeskey.rsaencrypted
        AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted, C:\Users\zeroadmin\tempdir\lorumipsum.txt.original,
                                            C:\Users\zeroadmin\tempdir\lorumipsum.aeskey.rsaencrypted}

    .EXAMPLE
        # Directory Encryption Example
        # NOTE: If neither -PathToCertFile nor -CNOfCertInStore parameters are used, a NEW Self-Signed Certificate is
        # created and added to Cert:\LocalMachine\My

        PS C:\Users\zeroadmin> New-EncryptedFile -ContentType Directory -ContentToEncrypt C:\Users\zeroadmin\tempdir
        Please enter the desired CN for the new Self-Signed Certificate: TempDirEncryption


        FilesEncryptedViaRSA               :
        FilesEncryptedViaAES               : {C:\Users\zeroadmin\tempdir\agricola.txt.aesencrypted, C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted,
                                            C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted}
        OriginalFiles                      : {C:\Users\zeroadmin\tempdir\agricola.txt.original, C:\Users\zeroadmin\tempdir\dolor.txt.original,
                                            C:\Users\zeroadmin\tempdir\lorumipsum.txt.original}
        CertficateUsedForRSAEncryption     : [Subject]
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

        LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My
        UnprotectedAESKey                  : BKcLSwqZjSq/D1RuqBGBxZ0dng+B3JwrWJVlhqgxrmo=
        RSAEncryptedAESKey                 : sUshzhMfrbO5FgOGw1Nsx9g5hrnsdUHsJdx8SltK8UeNcCWq8Rsk6dxC12NjrxUSHTSrPYdn5UycBqXB+PNltMebAj80I3Zsh5xRsSbVRSS+fzgGJTUw7ya98J
                                            7vKISUaurBTK4C4Czh1D2bgT7LNADO7qAUgbnv+xdqxgIexlOeNsEkzG10Tl+DxkUVgcpJYbznoTXPUVnj9AZkcczRd2EWPcV/WZnTZwmtH+Ill7wbXSG3R95d
                                            dbQLZfO0eOoBB/DAYWcPkifxJf+20s25xA8MKl7pNpDUbVhGhp61VCaaEqr6QlgihtluqWZeRgHEY3xSzz/UVHhzjCc6Rs9aPw==
        RSAEncryptedAESKeyLocation         : C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
        AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\agricola.txt.aesencrypted, C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted,
                                            C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted, C:\Users\zeroadmin\tempdir\agricola.txt.original...}


#>
function New-EncryptedFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [ValidateSet("String","ArrayOfStrings","File","Directory")]
        $ContentType,

        [Parameter(Mandatory=$True)]
        $ContentToEncrypt,

        [Parameter(Mandatory=$False)]
        [switch]$Recurse,

        [Parameter(Mandatory=$False)]
        $FileToOutput,

        [Parameter(Mandatory=$False)]
        $PathToCertFile,

        [Parameter(Mandatory=$False)]
        $CNofCertInStore,

        [Parameter(Mandatory=$False)]
        [securestring]$CertPwd
    )

    ##### BEGIN Parameter Validation #####

    if ($ContentToEncrypt.GetType().Fullname -eq "System.String" -and !$ContentType) {
        $ContentType = "String"
    }
    if ($ContentToEncrypt.GetType().Fullname -match "System.String\[\]|System.Object\[\]" -and !$ContentType) {
        $ContentType = "ArrayOfStrings"
    }

    if ($ContentType -match "String|ArrayOfStrings" -and !$FileToOutput) {
        $FileToOutput = Read-Host -Prompt "Please enter the full path to the new Encrypted File you would like to generate."
    }
    if ($ContentType -match "String|ArrayOfStrings" -and !$ContentToEncrypt) {
        $ContentToEncrypt = Read-Host -Prompt "Please enter the string that you would like to encrypt and output to $FileToOutput"
    }

    $RegexDirectoryPath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![.<>:"\/|?*]).)+$'
    $RegexFilePath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![<>:"\/|?*]).)+((.*?\.)|(.*?\.[\w]+))+$'
    if ($ContentType -eq "File" -and $ContentToEncrypt -notmatch $RegexFilePath) {
        Write-Verbose "The -ContentType specified was `"File`" but $ContentToEncrypt does not appear to be a valid file path. This is either because a full path was not provided of the file does not have a file extenstion. Please correct and try again. Halting!"
        Write-Error "The -ContentType specified was `"File`" but $ContentToEncrypt does not appear to be a valid file path. This is either because a full path was not provided of the file does not have a file extenstion. Please correct and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "File" -and $FileToOutput) {
        Write-Verbose "The -FileToOutput should NOT be used when -ContentType is `"File`". Simply use `"-ContentType File`" and output file naming convention will be handled automatically by the New-EncryptedFile function. Halting!"
        Write-Error "The -FileToOutput should NOT be used when -ContentType is `"File`". Simply use `"-ContentType File`" and output file naming convention will be handled automatically by the New-EncryptedFile function. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory" -and $ContentToEncrypt -notmatch $RegexDirectoryPath) {
        Write-Verbose "The -ContentType specified was `"Directory`" but $ContentToEncrypt does not appear to be a valid directory path. This is either because a full path was not provided or because the directory name ends with something similar to `".letters`". Please correct and try again. Halting!"
        Write-Error "The -ContentType specified was `"Directory`" but $ContentToEncrypt does not appear to be a valid directory path. This is either because a full path was not provided or because the directory name ends with something similar to `".letters`". Please correct and try again. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory" -and $FileToOutput) {
        Write-Verbose "The -FileToOutput should NOT be used when -ContentType is `"Directory`". Simply using `"-ContentType Directory`" will create new encrypted files in the specified Directory. Halting!"
        Write-Error "The -FileToOutput should NOT be used when -ContentType is `"Directory`". Simply using `"-ContentType Directory`" will create new encrypted files in the specified Directory. Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($Recurse -and $ContentType -ne "Directory") {
        Write-Verbose "The -Recurse switch should only be used when -ContentType is `"Directory`"! Halting!"
        Write-Error "The -Recurse switch should only be used when -ContentType is `"Directory`"! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($ContentType -eq "String" -and $ContentToEncrypt.GetType().FullName -ne "System.String") {
        Write-Verbose "ContentType 'String' was specified but the object passed to ContentToEncrypt is $($ContentToEncrypt.GetType().FullName). Halting!"
        Write-Error "ContentType 'String' was specified but the object passed to ContentToEncrypt is $($ContentToEncrypt.GetType().FullName). Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "ArrayofStrings" -and $ContentToEncrypt.GetType().FullName -notmatch "System.String\[\]|System.Object\[\]") {
        Write-Verbose "ContentType 'ArrayOfStrings' was specified but the object passed to ContentToEncrypt is $($ContentToEncrypt.GetType().FullName). Halting!"
        Write-Error "ContentType 'ArrayOfStrings' was specified but the object passed to ContentToEncrypt is $($ContentToEncrypt.GetType().FullName). Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "ArrayofStrings" -and $ContentToEncrypt.GetType().FullName -match "System.Object\[\]") {
        $InspectArrayObjects = $(foreach ($obj in $ContentToEncrypt) {
            $obj.GetType().FullName
        }) | Sort-Object | Get-Unique
        if ($InspectArrayObjects -ne "System.String") {
            Write-Verbose "Not all array elements in -ContentToEncrypt are of type System.String! Halting!"
            Write-Error "Not all array elements in -ContentToEncrypt are of type System.String! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if ($ContentType -eq "File" -and !$(Test-Path $ContentToEncrypt)) {
        Write-Verbose "The path $ContentToEncrypt was not found! Halting!"
        Write-Error "The path $ContentToEncrypt was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory" -and !$(Test-Path $ContentToEncrypt)) {
        Write-Verbose "The path $ContentToEncrypt was not found! Halting!"
        Write-Error "The path $ContentToEncrypt was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($ContentType -eq "Directory") {
        if ($Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem -Recurse $ContentToEncrypt | Where-Object {$_.PSIsContainer -eq $false}
        }
        if (!$Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem $ContentToEncrypt | Where-Object {$_.PSIsContainer -eq $false}
        }
        if ($PossibleFilesToEncrypt.Count -lt 1) {
            Write-Verbose "No files were found in the directory $ContentToEncrypt. Halting!"
            Write-Error "No files were found in the directory $ContentToEncrypt. Halting!"
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

    if ($PathToCertFile -and $CNofCertInStore) {
        Write-Host "Please use *either* a .pfx certificate file *or*  a certificate in the user's local certificate store to encrypt the file"
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
            Remove-Variable -Name "CNofCertInStore" -Force -ErrorAction SilentlyContinue
        }
        if ($WhichCertSwitch -eq "Store") {
            Remove-Variable -Name "PathToCertFile" -Force -ErrorAction SilentlyContinue
        }
    }

    # Validate PathToCertFile
    if ($PathToCertFile) { 
        if (! (Test-Path $PathToCertFile)) {
            Write-Host "The $PathToCertFile was not found. Please check to make sure the file exists."
            $PathToCertFile = Read-Host -Prompt "Please enter the full path to the .pfx certificate file. Example: C:\ps_scripting.pfx"
            if (! (Test-Path $PathToCertFile)) {
                Write-Error "The .pfx certificate file was not found at the path specified. Halting."
                $global:FunctionResult = "1"
                return
            }
        }

        # See if Cert is password protected
        try {
            # First, try null password
            $Cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToCertFile, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        }
        catch {
            Write-Host "Either the Private Key is Password Protected, or it is marked as Unexportable..."
            if (!$CertPwd) {
                $CertPwd = Read-Host -Prompt "Please enter the password for the certificate $($TestCertObj.Subject). If there is no password, simply press [ENTER]" -AsSecureString
            }

            # Next, try $CertPwd 
            try {
                $Cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToCertFile, $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
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

    # Validate CNofCertInStore
    if ($CNofCertInStore) {
        $Cert1 = $(Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=$CNofCertInStore"})

        if ($Cert1.Count -gt 1) {
            Write-Host "More than one Certificate with a CN beginning with CN=$CNofCertInStore has been identified. Only one Certificate may be used. 
            A list of available Certificates in the User Store are as follows:"
            foreach ($obj1 in $(Get-ChildItem "Cert:\LocalMachine\My").Subject) {$obj1.Split(",")[0]}
            $CNofCertInStore = Read-Host -Prompt "Please enter the CN of the Certificate you would like to use to encrypt the file"
            $Cert1 = $(Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=$CNofCertInStore"})
            if ($Cert1.Count -gt 1) {
                Write-Error "More than one Certificate with a CN beginning with CN=$CNofCertInStore has been identified. Only one Certificate may be used. Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($Cert1.Count -lt 1) {
            Write-Verbose "Unable to find a a certificate matching CN=$CNofCertInStore in `"Cert:\LocalMachine\My`"! Halting!"
            Write-Error "Unable to find a a certificate matching CN=$CNofCertInStore in `"Cert:\LocalMachine\My`"! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($(-not $PSBoundParameters['PathToCertFile']) -and $(-not $PSBoundParameters['CNofCertInStore'])) {
        if ($FileToOutput) {
            # Create the Self-Signed Cert and add it to the Personal Local Machine Store
            # Check to see if a Certificate with CN=$FileToOutputFileSansExt exists in the Local Machine Store already
            $LocalMachineCerts = Get-ChildItem Cert:\LocalMachine\My
            $FoundMatchingExistingCert = $LocalMachineCerts | Where-Object {$_.Subject -match "CN=$FileToOutputFileSansExt"}
            if ($FoundMatchingExistingCert.Count -gt 1) {
                $FoundMatchingExistingCert = $FoundMatchingExistingCert[0]
            }
            if ($FoundMatchingExistingCert) {
                $Cert1 = $FoundMatchingExistingCert
            }
            else {
                #$Cert1 = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DNSName "$FileToOutputFileSansExt" -KeyExportPolicy "Exportable"
                $Cert1Prep = Get-EncryptionCert -CommonName $FileToOutputFileSansExt -ExportDirectory $($FileToOutput | Split-Path -Parent)
                $Cert1 = $Cert1Prep.CertInfo
            }
        }
        else {
            $CNOfNewCert = Read-Host -Prompt "Please enter the desired CN for the new Self-Signed Certificate"

            # Check to see if a Certificate with CN=$FileToOutputFileSansExt exists in the Local Machine Store already
            $LocalMachineCerts = Get-ChildItem Cert:\LocalMachine\My
            $FoundMatchingExistingCert = $LocalMachineCerts | Where-Object {$_.Subject -match "CN=$CNOfNewCert"}
            if ($FoundMatchingExistingCert.Count -gt 0) {
                $UseExistingCertQuery = Read-Host -Prompt "There is already a Certificate with a Common Name (CN) matching $CNOfNewCert in the Local Machine Store. Would you like to use the *old* Certificate or create a *new* one? [old/new]"
                if ($UseExistingCertQuery -notmatch "old|new" -or $UseExistingCertQuery -eq "old") {
                    Write-Host "Using existing certificate..."
                    if ($FoundMatchingExistingCert.Count -gt 1) {
                        $FoundMatchingExistingCert = $FoundMatchingExistingCert[0]
                    }
                    $Cert1 = $FoundMatchingExistingCert
                }
                if ($UseExistingCertQuery -eq "new") {
                    #$Cert1 = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DNSName "$CNOfNewCert`ForEncryption" -KeyExportPolicy "Exportable"
                    $Cert1Prep = Get-EncryptionCert -CommonName $CNOfNewCert -ExportDirectory $HOME
                    $Cert1 = $Cert1Prep.CertInfo
                }
            }
            else {
                #$Cert1 = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DNSName "$CNOfNewCert" -KeyExportPolicy "Exportable"
                $Cert1Prep = Get-EncryptionCert -CommonName $CNOfNewCert -ExportDirectory $HOME
                $Cert1 = $Cert1Prep.CertInfo
            }
        }
    }

    # If user did not explicitly use $PathToCertFile, export the $Cert1 to a .pfx file in the same directory as $FileToOutput
    # so that it's abundantly clear that it was used for encryption, even if it's already in the Cert:\LocalMachine\My Store
    if (!$PathToCertFile) {
        $CertName = $($Cert1.Subject | Select-String -Pattern "^CN=[\w]+").Matches.Value -replace "CN=",""
        try {
            if ($FileToOutput) {
                $PfxOutputDir = $FileToOutput | Split-Path -Parent
            }
            if (!$FileToOutput -and $ContentType -eq "File") {
                $PfxOutputDir = $ContentToEncrypt | Split-Path -Parent
            }
            if (!$FileToOutput -and $ContentType -eq "Directory") {
                $PfxOutputDir = $ContentToEncrypt
            }
            $pfxbytes = $Cert1.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
            [System.IO.File]::WriteAllBytes("$PfxOutputDir\$CertName.pfx", $pfxbytes)
        }
        catch {
            Write-Warning "Either the Private Key is Password Protected or it is marked as Unexportable...Asking for password to try and generate new .pfx file..."
            # NOTE: The $Cert1.Export() method in the above try block has a second argument for PlainTextPassword, but it doesn't seem to work consistently
            
            # Check to see if it's already in the Cert:\LocalMachine\My Store
            if ($(Get-Childitem "Cert:\LocalMachine\My").Thumbprint -contains $Cert1.Thumbprint) {
                Write-Verbose "The certificate $CertName is already in the Cert:\LocalMachine\My Store."
            }
            else {
                Write-Host "Importing $CertName to Cert:\LocalMachine\My Store..."
                $X509Store = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                $X509Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $X509Store.Add($Cert1)
            }

            Write-Host "Attempting to export $CertName from Cert:\LocalMachine\My Store to .pfx file..."

            if (!$CertPwd) {
                $CertPwd = Read-Host -Prompt "Please enter the password for the private key in the certificate $CertName" -AsSecureString
            }

            try {
                $CertItem = Get-Item "Cert:\LocalMachine\My\$($Cert1.Thumbprint)"
                [System.IO.File]::WriteAllBytes("$PfxOutputDir\$CertName.pfx", $CertItem.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $CertPwd))
                #Export-PfxCertificate -FilePath "$PfxOutputDir\$CertName.pfx" -Cert "Cert:\LocalMachine\My\$($Cert1.Thumbprint)" -Password $CertPwd
                $ExportPfxCertificateSuccessful = $true
            }
            catch {
                Write-Host "Creating a .pfx of containing the public certificate used for encryption failed, but this is not strictly necessary and is only attempted for future convenience. Continuing..."
                $ExportPfxCertificateSuccessful = $false
            }
        }
    }

    # If $Cert1 does NOT have a PrivateKey, ask the user if they're ABSOLUTELY POSITIVE they have the private key
    # before proceeding with encryption
    if ($Cert1.PrivateKey -eq $null -and $Cert1.HasPrivateKey -eq $false -or $Cert1.HasPrivateKey -ne $true) {
        Write-Warning "Windows reports that there is NO Private Key associated with this System.Security.Cryptography.X509Certificates.X509Certificate2 object!"
        $ShouldWeContinue = Read-Host -Prompt "Are you ABSOLUTELY SURE you have the private key somewhere and want to proceed with encryption? [Yes\No]"
        if ($ShouldWeContinue -match "Y|y|Yes|yes") {
            $AreYouReallyCertain = Read-Host -Prompt "Are you REALLY REALLY CERTAIN you want to proceed with encryption? Encryption will NOT proceed unless you type the word 'Affirmative'"
            if ($AreYouReallyCertain -ne "Affirmative") {
                Write-Verbose "User specified halt! Halting!"
                Write-Error "User specified halt! Halting!"
                $global:FunctionResult = "1"
                return
            }
        }
        if ($ShouldWeContinue -notmatch "Y|y|Yes|yes") {
            Write-Verbose "User specified halt! Halting!"
            Write-Error "User specified halt! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Parameter Validation #####

    ##### BEGIN Main Body #####
    $MaxNumberOfBytesThatCanBeEncryptedViaRSA = ((2048 - 384) / 8) + 37
    if ($ContentType -eq "String") {
        $EncodedBytes1 = [system.text.encoding]::UTF8.GetBytes($ContentToEncrypt)

        if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            Write-Error "The string `$ContentToEncrypt is to large to encrypt via this method. Try writing it to a file first and then using this function to encrypt that file."
            $global:FunctionResult = "1"
            return
        }

        #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
        $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
        $EncryptedString1 | Out-File "$FileToOutput.rsaencrypted"

        $CertLocation = if ($PathToCertFile) {
            $PathToCertFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My"
        }
        elseif ($ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My","$PfxOutputDir\$CertName.pfx"
        }

        New-Variable -Name "Output" -Value $(
            [pscustomobject][ordered]@{
                FileEncryptedViaRSA                 = "$FileToOutput.rsaencrypted"
                FileEncryptedViaAES                 = $null
                OriginalFile                        = $null
                CertficateUsedForRSAEncryption      = $Cert1
                LocationOfCertUsedForRSAEncryption  = $CertLocation
                UnprotectedAESKey                   = $null
                RSAEncryptedAESKey                  = $null
                RSAEncryptedAESKeyLocation          = $null
                AllFileOutputs                      = $(if ($PathToCertFile) {"$FileToOutput.rsaencrypted"} else {"$FileToOutput.rsaencrypted","$PfxOutputDir\$CertName.pfx"})
            }
        )

        $Output
    }
    if ($ContentType -eq "ArrayOfStrings") {
        $RSAEncryptedFiles = @()
        for ($i=0; $i -lt $ContentToEncrypt.Count; $i++) {
            # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
            $EncodedBytes1 = [system.text.encoding]::UTF8.GetBytes($ContentToEncrypt[$i])

            if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
                Write-Warning "The string in index $i of the `$ContentToEncrypt array is to large to encrypt via this method. Skipping..."
                continue
            }

            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$FileToOutput$i.rsaencrypted"

            $RSAEncryptedFiles += "$FileToOutput$i.rsaencrypted"
        }

        $CertLocation = if ($PathToCertFile) {
            $PathToCertFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My"
        }
        elseif ($ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My","$PfxOutputDir\$CertName.pfx"
        }

        New-Variable -Name "Output" -Value $(
            [pscustomobject][ordered]@{
                FilesEncryptedViaRSA                = $RSAEncryptedFiles
                FilesEncryptedViaAES                = $null
                OriginalFiles                       = $null
                CertficateUsedForRSAEncryption      = $Cert1
                LocationOfCertUsedForRSAEncryption  = $CertLocation
                UnprotectedAESKey                   = $null
                RSAEncryptedAESKey                  = $null
                RSAEncryptedAESKeyLocation          = $null
                AllFileOutputs                      = $(if ($PathToCertFile) {"$FileToOutput.rsaencrypted"} else {"$FileToOutput.rsaencrypted","$PfxOutputDir\$CertName.pfx"})
            }
        )

        $Output
    }
    if ($ContentType -eq "File") {
        $OriginalFile = $ContentToEncrypt

        # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
        $EncodedBytes1 = Get-Content $ContentToEncrypt -Encoding Byte -ReadCount 0

        # If the file content is small enough, encrypt via RSA
        if ($EncodedBytes1.Length -lt $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$($(Get-ChildItem $ContentToEncrypt).BaseName).rsaencrypted"
        }
        # If the file content is too large, encrypt via AES and then Encrypt the AES Key via RSA
        if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            $AESKeyDir = $ContentToEncrypt | Split-Path -Parent
            $AESKeyFileNameSansExt = $(Get-ChildItem $ContentToEncrypt).BaseName

            # Copy the original file and update file name on copy to indicate it's the original
            Copy-Item -Path $ContentToEncrypt -Destination "$ContentToEncrypt.original"

            $AESKey = CreateAESKey
            $FileEncryptionInfo = EncryptFile $ContentToEncrypt $AESKey

            # Save $AESKey for later use in the same directory as $ContentToEncrypt
            # $bytes = [System.Convert]::FromBase64String($AESKey)
            # [System.IO.File]::WriteAllBytes("$AESKeyDir\$AESKeyFileNameSansExt.aeskey",$bytes)
            $FileEncryptionInfo.AESKey | Out-File "$AESKeyDir\$AESKeyFileNameSansExt.aeskey"

            # Encrypt the AESKey File using RSA asymetric encryption
            # NOTE: When Get-Content's -ReadCount is 0, all content is read in one fell swoop, so it's not an array of lines
            $EncodedBytes1 = Get-Content "$AESKeyDir\$AESKeyFileNameSansExt.aeskey" -Encoding Byte -ReadCount 0
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$AESKeyDir\$AESKeyFileNameSansExt.aeskey.rsaencrypted"
            Remove-Item "$AESKeyDir\$AESKeyFileNameSansExt.aeskey"
        }

        $FileEncryptedViaRSA = $(if (!$AESKey) {"$($(Get-ChildItem $ContentToEncrypt).BaseName).rsaencrypted"})
        $FileEncryptedViaAES = $(if ($AESKey) {$FileEncryptionInfo.FilesEncryptedwAESKey})
        $RSAEncryptedAESKeyLocation = $(if ($AESKey) {"$AESKeyDir\$AESKeyFileNameSansExt.aeskey.rsaencrypted"})
        $RSAEncryptedFileName = $(if ($FileEncryptedViaRSA) {$FileEncryptedViaRSA})
        $AESEncryptedFileName = if ($FileEncryptedViaAES) {$FileEncryptedViaAES}

        $AllFileOutputsPrep = $RSAEncryptedFileName,$AESEncryptedFileName,"$OriginalFile.original",$RSAEncryptedAESKeyLocation
        $AllFileOutputs = $AllFileOutputsPrep | foreach {if ($_ -ne $null) {$_}}
        if (!$PathToCertFile) {
            $AllFileOutputs = $AllFileOutputs + "$PfxOutputDir\$CertName.pfx"
        }

        $CertLocation = if ($PathToCertFile) {
            $PathToCertFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My"
        }
        elseif ($ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My","$PfxOutputDir\$CertName.pfx"
        }

        New-Variable -Name "Output" -Value $(
            [pscustomobject][ordered]@{
                FileEncryptedViaRSA                 = $FileEncryptedViaRSA
                FileEncryptedViaAES                 = $FileEncryptedViaAES
                OriginalFile                        = "$OriginalFile.original"
                CertficateUsedForRSAEncryption      = $Cert1
                LocationOfCertUsedForRSAEncryption  = $CertLocation
                UnprotectedAESKey                   = $(if ($AESKey) {$FileEncryptionInfo.AESKey})
                RSAEncryptedAESKey                  = $(if ($AESKey) {$EncryptedString1})
                RSAEncryptedAESKeyLocation          = $RSAEncryptedAESKeyLocation
                AllFileOutputs                      = $AllFileOutputs
            }
        )

        $Output
    }
    if ($ContentType -eq "Directory") {
        if (!$Recurse) {
            $FilesToEncryptPrep = $(Get-ChildItem $ContentToEncrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
        }
        if ($Recurse) {
            $FilesToEncryptPrep = $(Get-ChildItem -Recurse $ContentToEncrypt | Where-Object {$_.PSIsContainer -eq $false}).FullName
        }
        
        [array]$FilesToEncryptViaRSA = @()
        [array]$FilesToEncryptViaAES = @()
        foreach ($file in $FilesToEncryptPrep) {
            # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
            $EncodedBytes1 = Get-Content $file -Encoding Byte -ReadCount 0

            # If the file content is small enough, encrypt via RSA
            if ($EncodedBytes1.Length -lt $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
                $FilesToEncryptViaRSA += $file
            }
            if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
                $FilesToEncryptViaAES += $file
            }
        }
        foreach ($file in $FilesToEncryptViaAES) {
            # Copy the original file and update file name on copy to indicate it's the original
            Copy-Item -Path $file -Destination "$file.original"
        }

        # Start Doing the Encryption
        foreach ($file in $FilesToEncryptViaRSA) {
            $EncodedBytes1 = Get-Content $file -Encoding Byte -ReadCount 0
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$($(Get-ChildItem $file).BaseName).rsaencrypted"
        }

        $AESKeyDir = $ContentToEncrypt
        $AESKeyFileName = "$($AESKeyDir | Split-Path -Leaf).aeskey"
        $AESKey = CreateAESKey
        $FileEncryptionInfo = EncryptFile $FilesToEncryptViaAES $AESKey

        # Save $AESKey for later use in the same directory as $file
        # $bytes = [System.Convert]::FromBase64String($AESKey)
        # [System.IO.File]::WriteAllBytes("$AESKeyDir\$AESKeyFileName.aeskey",$bytes)
        $FileEncryptionInfo.AESKey | Out-File "$AESKeyDir\$AESKeyFileName"

        # Encrypt the AESKey File using RSA asymetric encryption
        # NOTE: When Get-Content's -ReadCount is 0, all content is read in one fell swoop, so it's not an array of lines
        $EncodedBytes1 = Get-Content "$AESKeyDir\$AESKeyFileName" -Encoding Byte -ReadCount 0
        $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
        $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
        $EncryptedString1 | Out-File "$AESKeyDir\$AESKeyFileName.rsaencrypted"
        Remove-Item "$AESKeyDir\$AESKeyFileName"

        $RSAEncryptedAESKeyLocation = if ($FilesToEncryptViaAES.Count -ge 1) {"$AESKeyDir\$AESKeyFileName.rsaencrypted"}
        $OriginalFilesPrep = $FilesToEncryptViaRSA + $FilesToEncryptViaAES
        $OriginalFiles = foreach ($file in $OriginalFilesPrep) {"$file.original"}
        $RSAEncryptedFileNames = foreach ($file in $FilesToEncryptViaRSA) {
            "$file.rsaencrypted"
        }
        $AESEncryptedFileNames = foreach ($file in $FilesToEncryptViaAES) {
            "$file.aesencrypted"
        }

        $AllFileOutputsPrep = $RSAEncryptedFileNames,$AESEncryptedFileNames,$OriginalFiles,$RSAEncryptedAESKeyLocation
        $AllFileOutputs = foreach ($element in $AllFileOutputsPrep) {if ($element -ne $null) {$element}}
        if (!$PathToCertFile) {
            $AllFileOutputs = $AllFileOutputs + "$PfxOutputDir\$CertName.pfx"
        }

        $CertLocation = if ($PathToCertFile) {
            $PathToCertFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My"
        }
        elseif ($ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My","$PfxOutputDir\$CertName.pfx"
        }

        New-Variable -Name "Output" -Value $(
            [pscustomobject][ordered]@{
                FilesEncryptedViaRSA                = $RSAEncryptedFileNames
                FilesEncryptedViaAES                = $AESEncryptedFileNames
                OriginalFiles                       = $OriginalFiles
                CertficateUsedForRSAEncryption      = $Cert1
                LocationOfCertUsedForRSAEncryption  = $CertLocation
                UnprotectedAESKey                   = $FileEncryptionInfo.AESKey
                RSAEncryptedAESKey                  = $EncryptedString1
                RSAEncryptedAESKeyLocation          = $RSAEncryptedAESKeyLocation
                AllFileOutputs                      = $AllFileOutputs
            }
        )

        $Output
    }

    ##### END Main Body #####
}