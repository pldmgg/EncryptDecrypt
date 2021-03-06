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
        to the -PathToPfxFile parameter, or from the Certificate in the Cert:\LocalMachine\My store that you provide
        to the -CNofCertInStore parameter of this function.

        You will SOMETIMES need the AES Key to decrypt larger files that were encrypted using AES encryption.

        IMPORTANT NOTE #2:
        It is up to you to store the public/private key pair and the RSA-encrypted AES Key appropriately.

        Note that the public/private key pair will be found EITHER in a .pfx file in the same directory as encrypted
        file outputs OR in Cert:\LocalMachine\My OR in BOTH locations. Note that the RSA-encrypted AES Key will be
        found in a file in the same directory as encrypted file outputs.

    .PARAMETER SourceType
        Optional, but HIGHLY recommended.

        This parameter takes a string with one of the following values:
            String
            ArrayOfStrings
            File
            Directory

        If -ContentToEncrypt is a string, -SourceType should be "String".
        If -ContentToEncrypt is an array of strings, -SourceType should be "ArrayOfStrings".
        If -ContentToEncrypt is a string that represents a full path to a file, -SourceType should be "File".
        If -ContentToEncrypt is a string that represents a full path to a directory, -SourceType should be "Directory".

    .PARAMETER ContentToEncrypt
        Mandatory.

        This parameter takes a string that is either:
            - A string
            - An array of strings
            - A string that represents a full path to a file
            - A string that represents a full path to a directory

    .PARAMETER Recurse
        Optional.

        This parameter is a switch. It should only be used if -SourceType is "Directory". The function will fail
        immediately if this parameter is used and -SourceType is NOT "Directory".

        If this switch is NOT used, only files immediately under the directory specified by -ContentToEncrypt are
        encrypted.

        If this switch IS used, all files immediately under the directory specified by -ContentToEncrypt AS WELL AS
        all files within subdirectories under the directory specified by -ContentToEncrypt are encrypted.

    .PARAMETER FileToOutput
        Optional.

        This parameter specifies a full path to a NEW file that will contain encrypted information. This parameter should
        ONLY be used if -SourceType is "String" or "ArrayOfStrings". If this parameter is used and -SourceType is NOT
        "String" or "ArrayOfStrings", the function will immediately fail.

    .PARAMETER PathToPfxFile
        Optional.

        This parameter takes a string that represents the full path to a .pfx file. The public certificate in
        the .pfx file will be used for RSA encryption.

        NOTE: RSA encryption is ALWAYS used by this function, either to encrypt the information directly or to encrypt the
        AES Key that was used to encrypt the information.

    .PARAMETER CNOfCertInStore
        Optional.

        This parameter takes a string that represents the Common Name (CN) of the public certificate used for RSA
        encryption. This certificate must already exist in the Local Machine Store (i.e. Cert:\LocalMachine\My).

        NOTE: RSA encryption is ALWAYS used by this function, either to encrypt the information directly or to encrypt the
        AES Key that was used to encrypt the information.

    .PARAMETER CNOfNewCert
        Optional.

        This parameter takes a string that represents the desired Common Name (CN) for the new Self-Signed
        Certificate.

        NOTE: RSA encryption is ALWAYS used by this function, either to encrypt the information directly or to encrypt the
        AES Key that was used to encrypt the information.

    .PARAMETER CertPwd
        Optional. (However, this parameter is mandatory if the certificate is password protected).

        This parameter takes a System.Security.SecureString that represents the password for the certificate.

        Use this parameter if the certificate is password protected.

    .PARAMETER RemoveOriginalFile
        Optional.

        This parameter is a switch. By default, original unencrypted files are not touched. Use this switch to remove
        the original unencrypted files.

    .EXAMPLE
        # String Encryption Example
        # NOTE: If neither -PathToPfxFile nor -CNOfCertInStore parameters are used, a NEW Self-Signed Certificate is
        # created and added to Cert:\LocalMachine\My

        PS C:\Users\zeroadmin> New-EncryptedFile -SourceType String -ContentToEncrypt "MyPLaInTeXTPwd321!" -FileToOutput $HOME\MyPwd.txt

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

        LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My\34F3526E85C04CEDC79F26C2B086E52CF75F91C3
        UnprotectedAESKey                  :
        RSAEncryptedAESKey                 :
        RSAEncryptedAESKeyLocation         :
        AllFileOutputs                     : C:\Users\zeroadmin\MyPwd.txt.rsaencrypted 

    .EXAMPLE
        # ArrayOfStrings Encryption Example
        PS C:\Users\zeroadmin> $foodarray = @("fruit","vegetables","meat")
        PS C:\Users\zeroadmin> New-EncryptedFile -SourceType ArrayOfStrings -ContentToEncrypt $foodarray -PathToPfxFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -FileToOutput $HOME\Food.txt

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
        PS C:\Users\zeroadmin> New-EncryptedFile -SourceType File -ContentToEncrypt C:\Users\zeroadmin\tempdir\lorumipsum.txt -CNofCertInStore "ZeroTest" -CertPwd $ZeroTestPwd

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
                                            34F3526E85C04CEDC79F26C2B086E52CF75F91C3

        LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My\34F3526E85C04CEDC79F26C2B086E52CF75F91C3
        UnprotectedAESKey                  : E0588dE3siWEOAyM7A5+6LKqC5tG1egxXTfsUUE5sNM=
        RSAEncryptedAESKey                 : NkKjOwd8T45u1Hpn0CL9m5zD/97PG9GNnJCShh0vOUTn+m+E2nLFxuW7ChKiHCVtP1vD2z+ckW3kk1va3PAfjw3/hfm9zi2qn4Xu7kPdWL1owDdQyvBuUPTc35
                                            FSqaIJxxdsqWLnUHo1PINY+2usIPT5tf57TbTKbAg5q/RXOzCeUS+QQ+nOKMgQGnadlUVyyIYo2JRdzzKaTSHRwK4QFdDk/PUy39ei2FVOIlwitiAkWTyjFAb6
                                            x+kMCgOVDuALGOyVVBdNe+BDrrWgqnfRSCHSZoQKfnkA0dj0tuE2coYNwGQ6SVUmiDrdklBrnKl69cIFf8lkTSsUqGdq9bbaag==
        RSAEncryptedAESKeyLocation         : C:\Users\zeroadmin\tempdir\lorumipsum.aeskey.rsaencrypted
        AllFileOutputs                     : {C:\Users\zeroadmin\tempdir\lorumipsum.txt.aesencrypted, C:\Users\zeroadmin\tempdir\lorumipsum.txt.original,
                                            C:\Users\zeroadmin\tempdir\lorumipsum.aeskey.rsaencrypted}

    .EXAMPLE
        # Directory Encryption Example
        # NOTE: If neither -PathToPfxFile nor -CNOfCertInStore parameters are used, a NEW Self-Signed Certificate is
        # created and added to Cert:\LocalMachine\My

        PS C:\Users\zeroadmin> New-EncryptedFile -SourceType Directory -ContentToEncrypt C:\Users\zeroadmin\tempdir
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

        LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My\F2EFEBB37C37844A230961447C7C91C1DE13F1A5
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
        [Parameter(Mandatory=$True)]
        [ValidateSet("String","ArrayOfStrings","File","Directory")]
        [string]$SourceType,

        [Parameter(Mandatory=$True)]
        [string[]]$ContentToEncrypt,

        [Parameter(Mandatory=$False)]
        [switch]$Recurse,

        [Parameter(Mandatory=$False)]
        [string]$FileToOutput,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("\.pfx$")]
        [string]$PathToPfxFile,

        [Parameter(Mandatory=$False)]
        [string]$CNofCertInStore,

        [Parameter(Mandatory=$False)]
        [string]$CNOfNewCert,

        [Parameter(Mandatory=$False)]
        [securestring]$CertPwd,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveOriginalFile
    )

    ##### BEGIN Parameter Validation #####

    if ($SourceType -match "String|ArrayOfStrings" -and !$FileToOutput) {
        $FileToOutput = Read-Host -Prompt "Please enter the full path to the new Encrypted File you would like to generate."
    }
    if ($SourceType -eq "File" -or $SourceType -eq "Directory" -and $FileToOutput) {
        $ErrMsg = "The -FileToOutput should NOT be used when -SourceType is 'File' or 'Directory'. " +
        "Simply use '-SourceType File' or '-SourceType Directory' and output naming convention will be " +
        "handled automatically by the New-EncryptedFile function. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }
    if ($Recurse -and $SourceType -ne "Directory") {
        Write-Verbose "The -Recurse switch should only be used when -SourceType is 'Directory'! Halting!"
        Write-Error "The -Recurse switch should only be used when -SourceType is 'Directory'! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($RemoveOriginalFile -and $SourceType -notmatch "File|Directory") {
        Write-Error "The -RemoveOriginalFile parameter should only be used when -SourceType is 'File' or 'Directory'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $RegexDirectoryPath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![.<>:"\/|?*]).)+$'
    $RegexFilePath = '^(([a-zA-Z]:\\)|(\\\\))((?![.<>:"\/\\|?*]).)+((?![<>:"\/|?*]).)+((.*?\.)|(.*?\.[\w]+))+$'
    # NOTE: The below Linux Regex representations are simply commonly used naming conventions - they are not
    # strict definitions of Linux File or Directory Path formats
    $LinuxRegexFilePath = '^((~)|(\/[\w^ ]+))+\/?([\w.])+[^.]$'
    $LinuxRegexDirectoryPath = '^((~)|(\/[\w^ ]+))+\/?$'
    if ($SourceType -eq "File" -and $ContentToEncrypt -notmatch $RegexFilePath -and
    $ContentToDecrypt -notmatch $LinuxRegexFilePath
    ) {
        $ErrMsg = "The -SourceType specified was 'File' but '$ContentToEncrypt' does not appear to " +
        "be a valid file path. This is either because a full path was not provided or because the file does " +
        "not have a file extenstion. Please correct and try again. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }
    if ($SourceType -eq "Directory" -and $ContentToEncrypt -notmatch $RegexDirectoryPath -and
    $ContentToDecrypt -notmatch $LinuxRegexDirectoryPath
    ) {
        $ErrMsg = "The -SourceType specified was 'Directory' but '$ContentToEncrypt' does not appear to be " +
        "a valid directory path. This is either because a full path was not provided or because the directory " +
        "name ends with something that appears to be a file extension. Please correct and try again. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }
    
    if ($SourceType -eq "File" -and !$(Test-Path $ContentToEncrypt)) {
        Write-Error "The path '$ContentToEncrypt' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($SourceType -eq "Directory" -and !$(Test-Path $ContentToEncrypt)) {
        Write-Error "The path '$ContentToEncrypt' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    if ($SourceType -eq "Directory") {
        if ($Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem -Path $ContentToEncrypt -File -Recurse
        }
        if (!$Recurse) {
            $PossibleFilesToEncrypt = Get-ChildItem -Path $ContentToEncrypt -File
        }
        if ($PossibleFilesToEncrypt.Count -lt 1) {
            Write-Error "No files were found in the directory '$ContentToEncrypt'. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($FileToOutput) {
        $FileToOutputDirectory = $FileToOutput | Split-Path -Parent
        $FileToOutputFile = $FileToOutput | Split-Path -Leaf
        $FileToOutputFileSansExt = $($FileToOutputFile.Split("."))[0]
        if (! $(Test-Path $FileToOutputDirectory)) {
            Write-Error "The directory '$FileToOutputDirectory' does not exist. Please check the path. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    if ($PathToPfxFile -and $CNofCertInStore) {
        $ErrMsg = "Please use *either* -PathToPfxFile *or* -CNOfCertInStore. Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    # Validate PathToPfxFile
    if ($PathToPfxFile) { 
        if (!$(Test-Path $PathToPfxFile)) {
            Write-Error "The path '$PathToPfxFile'was not found at the path specified. Halting."
            $global:FunctionResult = "1"
            return
        }

        # See if Cert is password protected
        try {
            # First, try null password
            $Cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToPfxFile, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        }
        catch {
            Write-Warning "Either the Private Key in '$PathToPfxFile' is Password Protected, or it is marked as Unexportable..."
            if (!$CertPwd) {
                $CertPwd = Read-Host -Prompt "Please enter the password for the certificate. If there is no password, simply press [ENTER]" -AsSecureString
            }

            # Next, try $CertPwd 
            try {
                $Cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PathToPfxFile, $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            }
            catch {
                $ErrMsg = "Either the password supplied for the Private Key in $PathToPfxFile' is " +
                "incorrect or it is not marked as Exportable! Halting!"
                Write-Error $ErrMsg
                $global:FunctionResult = "1"
                return
            }
        }
    }

    # Validate CNofCertInStore
    if ($CNofCertInStore) {
        [array]$Cert1 = @(Get-ChildItem "Cert:\LocalMachine\My" | Where-Object {$_.Subject -match "CN=$CNofCertInStore,"})

        if ($Cert1.Count -gt 1) {
            Write-Warning "Multiple certificates under 'Cert:\LocalMachine\My' with a CommonName '$CNofCertInStore' have been identified! They are as follows:"
            for ($i=0; $i -lt $Cert1.Count; $i++) {
                Write-Host "$i) " + "Subject: " + $Cert1[$i].Subject + ' | Thumbprint: ' + $Cert1[$i].Thumbprint
            }
            $ValidChoiceNumbers = 0..$($Cert1.Count-1)
            $CertChoicePrompt = "Please enter the number that corresponds to the Certificate that you " +
            "would like to use. [0..$($Cert1.Count-1)]"
            $CertChoice = Read-Host -Prompt $CertChoicePrompt
            while ($ValidChoiceNumbers -notcontains $CertChoice) {
                Write-Host "'$CertChoice' is not a valid choice number! Valid choice numbers are $($ValidChoiceNumbers -join ",")"
                $CertChoice = Read-Host -Prompt $CertChoicePrompt
            }
            
            $Cert1 = $Cert1[$CertChoice]
        }
        if ($Cert1.Count -lt 1) {
            Write-Error "Unable to find a a certificate matching CN=$CNofCertInStore in 'Cert:\LocalMachine\My'! Halting!"
            $global:FunctionResult = "1"
            return
        }
        if ($Cert1.Count -eq 1) {
            $Cert1 = $Cert1[0]
        }
    }

    if ($(-not $PSBoundParameters['PathToPfxFile']) -and $(-not $PSBoundParameters['CNofCertInStore'])) {
        if (!$FileToOutput -and !$CNOfNewCert) {
            $CNOfNewCert = Read-Host -Prompt "Please enter the desired CN for the new Self-Signed Certificate"
        }
        if ($FileToOutput -and !$CNofNewCert) {
            $CNOfNewCert = $FileToOutputFileSansExt
        }

        # Create the Self-Signed Cert and add it to the Personal Local Machine Store
        # Check to see if a Certificate with CN=$FileToOutputFileSansExt exists in the Local Machine Store already
        [array]$LocalMachineCerts = @(Get-ChildItem Cert:\LocalMachine\My)
        [array]$FoundMatchingExistingCert = @($LocalMachineCerts | Where-Object {$_.Subject -match "CN=$CNOfNewCert"})

        if ($FoundMatchingExistingCert.Count -gt 1) {
            Write-Warning "Multiple certificates under 'Cert:\LocalMachine\My' with a CommonName '$CNofCertInStore' have been identified!"

            $UseExistingCert = Read-Host -Prompt "Would you like to use and existing certificate? [Yes\No]"
            while (![bool]$($UseExistingCert -match "^yes$|^y$|^no$|^n$")) {
                Write-Host "'$UseExistingCert' is not a valid choice. Please enter either 'Yes' or 'No'"
                $UseExistingCert = Read-Host -Prompt "Would you like to use and existing certificate? [Yes\No]"
            }

            if ($UseExistingCert) {
                for ($i=0; $i -lt $Cert1.Count; $i++) {
                    Write-Host "$i) " + "Subject: " + $Cert1[$i].Subject + ' | Thumbprint: ' + $Cert1[$i].Thumbprint
                }
                $ValidChoiceNumbers = 0..$($Cert1.Count-1)
                $CertChoicePrompt = "Please enter the number that corresponds to the Certificate that you " +
                "would like to use. [0..$($Cert1.Count-1)]"
                $CertChoice = Read-Host -Prompt $CertChoicePrompt
                while ($ValidChoiceNumbers -notcontains $CertChoice) {
                    Write-Host "'$CertChoice' is not a valid choice number! Valid choice numbers are $($ValidChoiceNumbers -join ",")"
                    $CertChoice = Read-Host -Prompt $CertChoicePrompt
                }
                
                $Cert1 = $Cert1[$CertChoice]
            }
            else {
                if ($FileToOutput) {
                    $PfxOutputDir = $FileToOutput | Split-Path -Parent
                }
                if (!$FileToOutput -and $SourceType -eq "File") {
                    if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                        $PfxOutputDir = $ContentToEncrypt[0] | Split-Path -Parent
                    }
                    else {
                        $PfxOutputDir = $ContentToEncrypt | Split-Path -Parent
                    }
                }
                if (!$FileToOutput -and $SourceType -eq "Directory") {
                    if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                        $PfxOutputDir = $ContentToEncrypt[0]
                    }
                    else {
                        $PfxOutputDir = $ContentToEncrypt
                    }
                }

                $Cert1Prep = Get-EncryptionCert -CommonName $CNOfNewCert -ExportDirectory $PfxOutputDir
                $Cert1 = $Cert1Prep.CertInfo
            }
        }
        if ($FoundMatchingExistingCert.Count -eq 1) {
            $Cert1 = $FoundMatchingExistingCert[0]
        }
        if ($FoundMatchingExistingCert.Count -lt 1) {
            #$Cert1 = New-SelfSignedCertificate -CertStoreLocation "Cert:\LocalMachine\My" -DNSName "$FileToOutputFileSansExt" -KeyExportPolicy "Exportable"
            if ($FileToOutput) {
                $PfxOutputDir = $FileToOutput | Split-Path -Parent
            }
            if (!$FileToOutput -and $SourceType -eq "File") {
                if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                    $PfxOutputDir = $ContentToEncrypt[0] | Split-Path -Parent
                }
                else {
                    $PfxOutputDir = $ContentToEncrypt | Split-Path -Parent
                }
            }
            if (!$FileToOutput -and $SourceType -eq "Directory") {
                if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                    $PfxOutputDir = $ContentToEncrypt[0]
                }
                else {
                    $PfxOutputDir = $ContentToEncrypt
                }
            }

            $Cert1Prep = Get-EncryptionCert -CommonName $CNOfNewCert -ExportDirectory $PfxOutputDir
            $Cert1 = $Cert1Prep.CertInfo
        }
    }

    # Now we have $Cert1 (which is an X509Certificate2 object)

    # If user did not explicitly use $PathToPfxFile, export the $Cert1 to a .pfx file in the same directory as $FileToOutput
    # so that it's abundantly clear that it was used for encryption, even if it's already in the Cert:\LocalMachine\My Store
    if (!$PSBoundParameters['PathToPfxFile']) {
        $CertName = $($Cert1.Subject | Select-String -Pattern "^CN=[\w]+").Matches.Value -replace "CN=",""
        try {
            if ($FileToOutput) {
                $PfxOutputDir = $FileToOutput | Split-Path -Parent
            }
            if (!$FileToOutput -and $SourceType -eq "File") {
                if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                    $PfxOutputDir = $ContentToEncrypt[0] | Split-Path -Parent
                }
                else {
                    $PfxOutputDir = $ContentToEncrypt | Split-Path -Parent
                }
            }
            if (!$FileToOutput -and $SourceType -eq "Directory") {
                if ($ContentToEncrypt.GetType().FullName -eq "System.String[]") {
                    $PfxOutputDir = $ContentToEncrypt[0]
                }
                else {
                    $PfxOutputDir = $ContentToEncrypt
                }
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
                # IMPORTANT NOTE: For some reason, eventhough we have the X509Certificate2 object ($Cert1), it may not
                # have the Property 'PrivateKey' until we import it to the Cert:\LocalMachine\My and then export it.
                # This could be why why the above export in the ty block failed...
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
                $Cert1 = Get-Item "Cert:\LocalMachine\My\$($Cert1.Thumbprint)"
                [System.IO.File]::WriteAllBytes("$PfxOutputDir\$CertName.pfx", $Cert1.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $CertPwd))
                #Export-PfxCertificate -FilePath "$PfxOutputDir\$CertName.pfx" -Cert "Cert:\LocalMachine\My\$($Cert1.Thumbprint)" -Password $CertPwd
                $ExportPfxCertificateSuccessful = $true
            }
            catch {
                Write-Warning "Creating a .pfx file containing the public certificate used for encryption failed, but this is not strictly necessary and is only attempted for convenience. Continuing..."
                $ExportPfxCertificateSuccessful = $false
            }
        }
    }

    # If $Cert1 does NOT have a PrivateKey, ask the user if they're ABSOLUTELY POSITIVE they have the private key
    # before proceeding with encryption
    if ($Cert1.PrivateKey -eq $null -and $Cert1.HasPrivateKey -ne $True) {
        Write-Warning "Windows reports that there is NO Private Key associated with this X509Certificate2 object!"
        $ShouldWeContinue = Read-Host -Prompt "Are you ABSOLUTELY SURE you have the private key somewhere and want to proceed with encryption? [Yes\No]"
        if (![bool]$($ShouldWeContinue -match "^yes$|^y$")) {
            Write-Verbose "User specified halt! Halting!"
            Write-Error "User specified halt! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    ##### END Parameter Validation #####

    ##### BEGIN Main Body #####
    $MaxNumberOfBytesThatCanBeEncryptedViaRSA = ((2048 - 384) / 8) + 37
    if ($SourceType -eq "String") {
        $EncodedBytes1 = [system.text.encoding]::UTF8.GetBytes($ContentToEncrypt)

        if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            Write-Error "The string `$ContentToEncrypt is to large to encrypt via this method. Try writing it to a file first and then using this function to encrypt that file."
            $global:FunctionResult = "1"
            return
        }

        #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
        <#
        try {
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        }
        catch {
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        }
        #>
        $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
        $EncryptedString1 | Out-File "$FileToOutput.rsaencrypted"

        $CertLocation = if ($PathToPfxFile) {
            $PathToPfxFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint
        }
        elseif ($ExportPfxCertificateSuccessful) {
            $("Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint),"$PfxOutputDir\$CertName.pfx"
        }

        [pscustomobject]@{
            FileEncryptedViaRSA                 = "$FileToOutput.rsaencrypted"
            FileEncryptedViaAES                 = $null
            OriginalFile                        = $null
            CertficateUsedForRSAEncryption      = $Cert1
            LocationOfCertUsedForRSAEncryption  = $CertLocation
            UnprotectedAESKey                   = $null
            RSAEncryptedAESKey                  = $null
            RSAEncryptedAESKeyLocation          = $null
            AllFileOutputs                      = $(if ($PathToPfxFile) {"$FileToOutput.rsaencrypted"} else {"$FileToOutput.rsaencrypted","$PfxOutputDir\$CertName.pfx"})
        }
    }
    if ($SourceType -eq "ArrayOfStrings") {
        $RSAEncryptedFiles = @()
        for ($i=0; $i -lt $ContentToEncrypt.Count; $i++) {
            # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
            $EncodedBytes1 = [system.text.encoding]::UTF8.GetBytes($ContentToEncrypt[$i])

            if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
                Write-Warning "The string in index $i of the `$ContentToEncrypt array is to large to encrypt via this method. Skipping..."
                continue
            }

            #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            <#
            try {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
            }
            catch {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            }
            #>
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $FileOutputPathSplit = $FileToOutput -split "\."
            $FileToOutputUpdated = $FileOutputPathSplit[0] + "_$i." + $FileOutputPathSplit[-1] + ".rsaencrypted"
            $EncryptedString1 | Out-File $FileToOutputUpdated

            $RSAEncryptedFiles += $FileToOutputUpdated
        }

        $CertLocation = if ($PathToPfxFile) {
            $PathToPfxFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint
        }
        elseif ($ExportPfxCertificateSuccessful) {
            $("Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint),"$PfxOutputDir\$CertName.pfx"
        }

        [pscustomobject]@{
            FilesEncryptedViaRSA                = $RSAEncryptedFiles
            FilesEncryptedViaAES                = $null
            OriginalFiles                       = $null
            CertficateUsedForRSAEncryption      = $Cert1
            LocationOfCertUsedForRSAEncryption  = $CertLocation
            UnprotectedAESKey                   = $null
            RSAEncryptedAESKey                  = $null
            RSAEncryptedAESKeyLocation          = $null
            AllFileOutputs                      = $(if ($PathToPfxFile) {$RSAEncryptedFiles} else {$RSAEncryptedFiles,"$PfxOutputDir\$CertName.pfx"})
        }
    }
    if ($SourceType -eq "File") {
        $OriginalFileItem = Get-Item $ContentToEncrypt
        $OriginalFile = $OriginalFileItem.FullName
        $OriginalFileName = $OriginalFileItem.Name
        $OriginalDirectory = $OriginalFileItem.Directory

        # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
        #$EncodedBytes1 = Get-Content $ContentToEncrypt -Encoding Byte -ReadCount 0
        $EncodedBytes1 = [System.IO.File]::ReadAllBytes($ContentToEncrypt)

        # If the file content is small enough, encrypt via RSA
        if ($EncodedBytes1.Length -lt $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            <#
            try {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
            }
            catch {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            }
            #>
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$OriginalDirectory\$OriginalFileName.rsaencrypted"
        }
        # If the file content is too large, encrypt via AES and then Encrypt the AES Key via RSA
        if ($EncodedBytes1.Length -ge $MaxNumberOfBytesThatCanBeEncryptedViaRSA) {
            $AESKeyDir = $ContentToEncrypt | Split-Path -Parent
            $AESKeyFileNameSansExt = $(Get-ChildItem $ContentToEncrypt).BaseName

            # Copy the original file and update file name on copy to indicate it's the original
            Copy-Item -Path $ContentToEncrypt -Destination "$OriginalFile.original"

            $AESKey = NewCryptographyKey -AsPlainText
            $FileEncryptionInfo = EncryptFile $ContentToEncrypt $AESKey

            # Save $AESKey for later use in the same directory as $ContentToEncrypt
            # $bytes = [System.Convert]::FromBase64String($AESKey)
            # [System.IO.File]::WriteAllBytes("$AESKeyDir\$AESKeyFileNameSansExt.aeskey",$bytes)
            $FileEncryptionInfo.AESKey | Out-File "$AESKeyDir\$AESKeyFileNameSansExt.aeskey"

            # Encrypt the AESKey File using RSA asymetric encryption
            # NOTE: When Get-Content's -ReadCount is 0, all content is read in one fell swoop, so it's not an array of lines
            #$EncodedBytes1 = Get-Content "$AESKeyDir\$AESKeyFileNameSansExt.aeskey" -Encoding Byte -ReadCount 0
            $EncodedBytes1 = [System.IO.File]::ReadAllBytes("$AESKeyDir\$AESKeyFileNameSansExt.aeskey")
            #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            <#
            try {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
            }
            catch {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            }
            #>
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$AESKeyDir\$AESKeyFileNameSansExt.aeskey.rsaencrypted"
            Remove-Item "$AESKeyDir\$AESKeyFileNameSansExt.aeskey"
        }

        $FileEncryptedViaRSA = if (!$AESKey) {"$OriginalFile.rsaencrypted"}
        $FileEncryptedViaAES = if ($AESKey) {$FileEncryptionInfo.FilesEncryptedwAESKey}
        $RSAEncryptedAESKeyLocation = if ($AESKey) {"$AESKeyDir\$AESKeyFileNameSansExt.aeskey.rsaencrypted"}
        $RSAEncryptedFileName = if ($FileEncryptedViaRSA) {$FileEncryptedViaRSA}
        $AESEncryptedFileName = if ($FileEncryptedViaAES) {$FileEncryptedViaAES}

        $AllFileOutputsPrep = $RSAEncryptedFileName,$AESEncryptedFileName,"$OriginalFile.original",$RSAEncryptedAESKeyLocation
        $AllFileOutputs = $AllFileOutputsPrep | foreach {if ($_ -ne $null) {$_}}
        if (!$PathToPfxFile) {
            $AllFileOutputs = $AllFileOutputs + "$PfxOutputDir\$CertName.pfx"
        }

        $CertLocation = if ($PathToPfxFile) {
            $PathToPfxFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint
        }
        elseif ($ExportPfxCertificateSuccessful) {
            $("Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint),"$PfxOutputDir\$CertName.pfx"
        }
        
        $RenameItemSplatParams = @{
            Path        = "$OriginalFile.original"
            NewName     = $OriginalFile
            PassThru    = $True
            ErrorAction = "SilentlyContinue"
        }
        $FinalOriginalFileItem = Rename-Item @RenameItemSplatParams
        if ($RemoveOriginalFile) {
            Remove-Item -Path $FinalOriginalFileItem.FullName -Force -ErrorAction SilentlyContinue
        }
        

        [pscustomobject]@{
            FileEncryptedViaRSA                 = $FileEncryptedViaRSA
            FileEncryptedViaAES                 = $FileEncryptedViaAES
            OriginalFile                        = $FinalOriginalFileItem.FullName
            CertficateUsedForRSAEncryption      = $Cert1
            LocationOfCertUsedForRSAEncryption  = $CertLocation
            UnprotectedAESKey                   = $(if ($AESKey) {$FileEncryptionInfo.AESKey})
            RSAEncryptedAESKey                  = $(if ($AESKey) {$EncryptedString1})
            RSAEncryptedAESKeyLocation          = $RSAEncryptedAESKeyLocation
            AllFileOutputs                      = $AllFileOutputs
        }
    }
    if ($SourceType -eq "Directory") {
        if (!$Recurse) {
            $FilesToEncryptPrep = $(Get-ChildItem -Path $ContentToEncrypt -File).FullName
        }
        if ($Recurse) {
            $FilesToEncryptPrep = $(Get-ChildItem -Path $ContentToEncrypt -Recurse -File).FullName
        }
        
        [array]$FilesToEncryptViaRSA = @()
        [array]$FilesToEncryptViaAES = @()
        foreach ($file in $FilesToEncryptPrep) {
            # Determine if the contents of the File is too long for Asymetric RSA Encryption with pub cert and priv key
            #$EncodedBytes1 = Get-Content $file -Encoding Byte -ReadCount 0
            $EncodedBytes1 = [System.IO.File]::ReadAllBytes($file)

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
            #$EncodedBytes1 = Get-Content $file -Encoding Byte -ReadCount 0
            $EncodedBytes1 = [System.IO.File]::ReadAllBytes($file)
            #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
            <#
            try {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
            }
            catch {
                $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            }
            #>
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            $EncryptedString1 = [System.Convert]::ToBase64String($EncryptedBytes1)
            $EncryptedString1 | Out-File "$file.rsaencrypted"
        }

        $AESKeyDir = $ContentToEncrypt
        $AESKeyFileName = "$($AESKeyDir | Split-Path -Leaf).aeskey"
        $AESKey = NewCryptographyKey -AsPlainText
        $FileEncryptionInfo = EncryptFile $FilesToEncryptViaAES $AESKey

        # Save $AESKey for later use in the same directory as $file
        # $bytes = [System.Convert]::FromBase64String($AESKey)
        # [System.IO.File]::WriteAllBytes("$AESKeyDir\$AESKeyFileName.aeskey",$bytes)
        $FileEncryptionInfo.AESKey | Out-File "$AESKeyDir\$AESKeyFileName"

        # Encrypt the AESKey File using RSA asymetric encryption
        # NOTE: When Get-Content's -ReadCount is 0, all content is read in one fell swoop, so it's not an array of lines
        #$EncodedBytes1 = Get-Content "$AESKeyDir\$AESKeyFileName" -Encoding Byte -ReadCount 0
        $EncodedBytes1 = [System.IO.File]::ReadAllBytes("$AESKeyDir\$AESKeyFileName")
        #$EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, $true)
        <#
        try {
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        }
        catch {
            $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        }
        #>
        $EncryptedBytes1 = $Cert1.PublicKey.Key.Encrypt($EncodedBytes1, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
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
        if (!$PathToPfxFile) {
            $AllFileOutputs = $AllFileOutputs + "$PfxOutputDir\$CertName.pfx"
        }

        $CertLocation = if ($PathToPfxFile) {
            $PathToPfxFile
        } 
        elseif (!$ExportPfxCertificateSuccessful) {
            "Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint
        }
        elseif ($ExportPfxCertificateSuccessful) {
            $("Cert:\LocalMachine\My" + '\' + $Cert1.Thumbprint),"$PfxOutputDir\$CertName.pfx"
        }

        [System.Collections.ArrayList]$FinalOriginalFileItems = @()
        foreach ($FullFilePath in $OriginalFiles) {
            $RenameItemSplatParams = @{
                Path        = $FullFilePath
                NewName     = $($FullFilePath -replace "\.original","")
                PassThru    = $True
                ErrorAction = "SilentlyContinue"
            }
            $FinalOriginalFileItem = Rename-Item @RenameItemSplatParams
            $null = $FinalOriginalFileItems.Add($FinalOriginalFileItem)
            if ($RemoveOriginalFile) {
                Remove-Item -Path $FullFilePath -Force -ErrorAction SilentlyContinue
            }
        }

        [pscustomobject]@{
            FilesEncryptedViaRSA                = $RSAEncryptedFileNames
            FilesEncryptedViaAES                = $AESEncryptedFileNames
            OriginalFiles                       = $FinalOriginalFileItems.FullName
            CertficateUsedForRSAEncryption      = $Cert1
            LocationOfCertUsedForRSAEncryption  = $CertLocation
            UnprotectedAESKey                   = $FileEncryptionInfo.AESKey
            RSAEncryptedAESKey                  = $EncryptedString1
            RSAEncryptedAESKeyLocation          = $RSAEncryptedAESKeyLocation
            AllFileOutputs                      = $AllFileOutputs
        }
    }

    ##### END Main Body #####
}

# SIG # Begin signature block
# MIIMaAYJKoZIhvcNAQcCoIIMWTCCDFUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU2vz6NOhqQssrGPqKOUZ0mvC+
# 7+egggndMIIEJjCCAw6gAwIBAgITawAAAERR8umMlu6FZAAAAAAARDANBgkqhkiG
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
# BDEWBBRRLE1K9sxKKeTByRQqvD884fK0WDANBgkqhkiG9w0BAQEFAASCAQC/cXOQ
# c49uexyMPAvqnzg7BZDv4AAoEkMxnI/GRhYNUwv3LhpZkhtKc0nNhIfzYVbA4Kok
# wHHzRia6vfltc5sj7APdoDQzhHZ0pShuuo6ZXDm3ElK1yFlyJebcZp7r1fE74wWH
# +Mv6XJHfCcwfviRy8Wa4KwTgDRTQErGYRYWBUqXpiUJ77DYoV6kxPFCTA3Ob+97W
# Q6utr1Fq2YemkCK0kNtDYmpiOloYzyPjZnI28+w8YyiKzIZ/bKnS8ASlvZLTnFNk
# BvHLznxzYnBT0RtFZiNND2rMMzHmdSV24c/uFoEhE4tkklD0ukez7v+8O9hdMZxT
# z1QYHytREjPF4v2w
# SIG # End signature block
