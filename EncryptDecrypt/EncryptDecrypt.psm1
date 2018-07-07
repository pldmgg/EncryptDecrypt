[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    $ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
}

# NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
# add it the the -RequiredModules string array just to be certain
$InvModDepSplatParams = @{
    RequiredModules                     = $ModulesToInstallAndImport
    InstallModulesNotAvailableLocally   = $True
    ErrorAction                         = "SilentlyContinue"
    WarningAction                       = "SilentlyContinue"
}
$ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams

if ($LoadModuleDependenciesResult.UnacceptableUnloadedModules.Count -gt 0) {
    Write-Warning "The following Modules were not able to be loaded:`n$($LoadModuleDependenciesResult.UnacceptableUnloadedModules.ModuleName -join "`n")"

    if ($PSVersionTable.PSEdition -eq "Core" -and $PSVersionTable.Platform -eq "Win32NT") {

        Write-Warning "'EncryptDecrypt' will probably not work with PowerShell Core..."

    }
}

# Public Functions



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
        PS C:\Users\zeroadmin> Get-DecryptedContent -ContentType String -ContentToDecrypt $EncryptedStringTest -PathToCertFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -NoFileOutput

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
        PS C:\Users\zeroadmin> Get-DecryptedContent -ContentType ArrayOfStrings -ContentToDecrypt $enctextarray -PathToCertFile C:\Users\zeroadmin\other\ArrayOfStrings.pfx -NoFileOutput
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
        PS C:\Users\zeroadmin> Get-DecryptedContent -ContentType File -ContentToDecrypt C:\Users\zeroadmin\tempdir\dolor.txt.aesencrypted -CNofCertInStore TempDirEncryption -AESKeyLocation C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
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
        PS C:\Users\zeroadmin> Get-DecryptedContent -ContentType Directory -ContentToDecrypt C:\Users\zeroadmin\tempdir -Recurse -CNofCertInStore TempDirEncryption -AESKeyLocation C:\Users\zeroadmin\tempdir\tempdir.aeskey.rsaencrypted
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


<#
    .SYNOPSIS
        This function uses openssl.exe to extract all public certificates and private key from a .pfx file. Each public certificate
        and the private key is written to its own separate file in the specified. OutputDirectory. If openssl.exe is not available
        on the current system, it is downloaded to the Current User's Downloads folder and added to $env:Path.

        NOTE: Nothing is installed.

    .DESCRIPTION
        See SYNOPSIS.

    .NOTES
        Depends on openssl.exe.

        NOTE: Nothing needs to be installed in order to use openssl.exe.

    .PARAMETER PFXFilePath
        Mandatory.

        This parameter takes a string that represents the full path to a .pfx file

    .PARAMETER PFXFilePwd
        Optional.

        This parameter takes a string (i.e. plain text password) or a secure string.

        If the private key in the .pfx file is password protected, use this parameter.

    .PARAMETER StripPrivateKeyPwd
        Optional.

        This parameter takes a boolean $true or $false.

        By default, this function writes the private key within the .pfx to a file in a protected format, i.e.
            -----BEGIN PRIVATE KEY-----
            -----END PRIVATE KEY-----

        If you set this parameter to $true, then this function will ALSO (in addition to writing out the above protected
        format to its own file) write the unprotected private key to its own file with format
            -----BEGIN RSA PRIVATE KEY----
            -----END RSA PRIVATE KEY----

        WARNING: This parameter is set to $true by default.

    .PARAMETER OutputDirectory
        Optional.

        This parameter takes a string that represents a file path to a *directory* that will contain all file outputs.

        If this parameter is not used, all file outputs are written to the same directory as the .pfx file.

    .PARAMETER DownloadAndAddOpenSSLToPath
        Optional.

        This parameter downloads openssl.exe from https://indy.fulgan.com/SSL/ to the current user's Downloads folder,
        and adds openssl.exe to $env:Path.

        WARNING: If openssl.exe is not already part of your $env:Path prior to running this function, this parameter
        becomes MANDATORY, or the function will fail.

    .EXAMPLE
        # If your private key is password protected...
        $PSSigningCertFile = "C:\Certs\Testing2\ZeroCode.pfx"
        $PFXSigningPwdAsSecureString = Read-Host -Prompt "Please enter the private key's password" -AsSecureString
        $OutDir = "C:\Certs\Testing2"

        Extract-PFXCerts -PFXFilePath $PSSigningCertFile `
        -PFXFilePwd $PFXSigningPwdAsSecureString `
        -StripPrivateKeyPwd $true `
        -OutputDirectory $OutDir

    .EXAMPLE
        # If your private key is NOT password protected...
        $PSSigningCertFile = "C:\Certs\Testing2\ZeroCode.pfx"
        $OutputDirectory = "C:\Certs\Testing2"

        Extract-PFXCerts -PFXFilePath $PSSigningCertFile `
        -StripPrivateKeyPwd $true `
        -OutputDirectory $OutDir
#>
function Extract-PfxCerts {
    [CmdletBinding(
        PositionalBinding=$true,
        ConfirmImpact='Medium'
    )]
    Param(
        [Parameter(Mandatory=$False)]
        [string]$PFXFilePath = $(Read-Host -Prompt "Please enter the full path to the .pfx file."),

        [Parameter(Mandatory=$False)]
        $PFXFilePwd, # This is only needed if the .pfx contains a password-protected private key, which should be the case 99% of the time

        [Parameter(Mandatory=$False)]
        [bool]$StripPrivateKeyPwd = $true,

        [Parameter(Mandatory=$False)]
        [string]$OutputDirectory, # If this parameter is left blank, all output files will be in the same directory as the original .pfx

        [Parameter(Mandatory=$False)]
        [switch]$DownloadAndAddOpenSSLToPath
    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####
    # Check for Win32 or Win64 OpenSSL Binary
    if (! $(Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        if ($DownloadAndAddOpenSSLToPath) {
            Write-Host "Downloading openssl.exe from https://indy.fulgan.com/SSL/..."
            $LatestWin64OpenSSLVer = $($($(Invoke-WebRequest -Uri https://indy.fulgan.com/SSL/).Links | Where-Object {$_.href -like "*[a-z]-x64*"}).href | Sort-Object)[-1]
            Invoke-WebRequest -Uri "https://indy.fulgan.com/SSL/$LatestWin64OpenSSLVer" -OutFile "$env:USERPROFILE\Downloads\$LatestWin64OpenSSLVer"
            $SSLDownloadUnzipDir = $(Get-ChildItem "$env:USERPROFILE\Downloads\$LatestWin64OpenSSLVer").BaseName
            if (! $(Test-Path "$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir")) {
                New-Item -Path "$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir" -ItemType Directory
            }
            UnzipFile -PathToZip "$env:USERPROFILE\Downloads\$LatestWin64OpenSSLVer" -TargetDir "$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir"
            # Add OpenSSL to $env:Path
            if ($env:Path[-1] -eq ";") {
                $env:Path = "$env:Path$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir"
            }
            else {
                $env:Path = "$env:Path;$env:USERPROFILE\Downloads\$SSLDownloadUnzipDir"
            }
        }
        else {
            Write-Verbose "The Extract-PFXCerts function requires openssl.exe. Openssl.exe cannot be found on this machine. Use the -DownloadAndAddOpenSSLToPath parameter to download openssl.exe and add it to `$env:Path. NOTE: Openssl.exe does NOT require installation. Halting!"
            Write-Error "The Extract-PFXCerts function requires openssl.exe. Openssl.exe cannot be found on this machine. Use the -DownloadAndAddOpenSSLToPath parameter to download openssl.exe and add it to `$env:Path. NOTE: Openssl.exe does NOT require installation. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # OpenSSL can't handle PowerShell SecureStrings, so need to convert it back into Plain Text
    if ($PFXFilePwd) {
        if ($PFXFilePwd.GetType().FullName -eq "System.Security.SecureString") {
            $PwdForPFXOpenSSL = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXFilePwd))
        }
        if ($PFXFilePwd.GetType().FullName -eq "System.String") {
            $PwdForPFXOpenSSL = $PFXFilePwd
        }
    }

    $privpos = $PFXFilePath.LastIndexOf("\")
    $PFXFileDir = $PFXFilePath.Substring(0, $privpos)
    $PFXFileName = $PFXFilePath.Substring($privpos+1)
    $PFXFileNameSansExt = $($PFXFileName.Split("."))[0]

    if (!$OutputDirectory) {
        $OutputDirectory = $PFXFileDir
    }

    $ProtectedPrivateKeyOut = "$PFXFileNameSansExt"+"_protected_private_key"+".pem"
    $UnProtectedPrivateKeyOut = "$PFXFileNameSansExt"+"_unprotected_private_key"+".pem"
    $AllPublicKeysInChainOut = "$PFXFileNameSansExt"+"_all_public_keys_in_chain"+".pem"
    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Parameter Validation #####
    if (!$(Test-Path $PFXFilePath)) {
        Write-Verbose "The path $PFXFilePath was not found! Halting!"
        Write-Error "The path $PFXFilePath was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (! $(Test-Path $OutputDirectory)) {
        Write-Verbose "The path $OutputDirectory was not found! Halting!"
        Write-Error "The path $OutputDirectory was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }
    
    ##### END Parameter Validation #####


    ##### BEGIN Main Body #####
    # The .pfx File could (and most likely does) contain a private key
    # Extract Private Key and Keep It Password Protected
    try {
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = "openssl.exe"
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nocerts -out $OutputDirectory\$ProtectedPrivateKeyOut -nodes -password pass:$PwdForPFXOpenSSL"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        $Process.WaitForExit()
        $stdout = $Process.StandardOutput.ReadToEnd()
        $stderr = $Process.StandardError.ReadToEnd()
        $AllOutput = $stdout + $stderr

        if ($AllOutput -match "error") {
            Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect. However, it may be that at this stage in the process, it is not protected with a password. Trying without password..."
            throw
        }
    }
    catch {
        try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = "openssl.exe"
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nocerts -out $OutputDirectory\$ProtectedPrivateKeyOut -nodes -password pass:"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $AllOutput = $stdout + $stderr

            if ($AllOutput -match "error") {
                Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect."
                throw
            }
        }
        catch {
            $PFXFilePwdFailure = $true
        }
    }
    if ($PFXFilePwdFailure -eq $true) {
        Write-Verbose "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
        Write-Error "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
        $global:FunctionResult = "1"
        return
    }
    

    if ($StripPrivateKeyPwd) {
        # Strip Private Key of Password
        & openssl.exe rsa -in "$PFXFileDir\$ProtectedPrivateKeyOut" -out "$OutputDirectory\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
    }

    New-Variable -Name "$PFXFileNameSansExt`PrivateKeyInfo" -Value $(
        if ($StripPrivateKeyPwd) {
            [pscustomobject][ordered]@{
                ProtectedPrivateKeyFilePath     = "$OutputDirectory\$ProtectedPrivateKeyOut"
                UnProtectedPrivateKeyFilePath   = "$OutputDirectory\$UnProtectedPrivateKeyOut"
            }
        }
        else {
            [pscustomobject][ordered]@{
                ProtectedPrivateKeyFilePath     = "$OutputDirectory\$ProtectedPrivateKeyOut"
                UnProtectedPrivateKeyFilePath   = $null
            }
        }
    )
    

    # Setup $ArrayOfPubCertPSObjects for PSCustomObject Collection
    $ArrayOfPubCertPSObjects = @()
    # The .pfx File Also Contains ALL Public Certificates in Chain 
    # The below extracts ALL Public Certificates in Chain
    try {
        $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
        $ProcessInfo.FileName = "openssl.exe"
        $ProcessInfo.RedirectStandardError = $true
        $ProcessInfo.RedirectStandardOutput = $true
        $ProcessInfo.UseShellExecute = $false
        $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nokeys -out $OutputDirectory\$AllPublicKeysInChainOut -password pass:$PwdForPFXOpenSSL"
        $Process = New-Object System.Diagnostics.Process
        $Process.StartInfo = $ProcessInfo
        $Process.Start() | Out-Null
        $Process.WaitForExit()
        $stdout = $Process.StandardOutput.ReadToEnd()
        $stderr = $Process.StandardError.ReadToEnd()
        $AllOutput = $stdout + $stderr

        if ($AllOutput -match "error") {
            Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect. However, it may be that at this stage in the process, it is not protected with a password. Trying without password..."
            throw
        }
    }
    catch {
        try {
            $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
            $ProcessInfo.FileName = "openssl.exe"
            $ProcessInfo.RedirectStandardError = $true
            $ProcessInfo.RedirectStandardOutput = $true
            $ProcessInfo.UseShellExecute = $false
            $ProcessInfo.Arguments = "pkcs12 -in $PFXFilePath -nokeys -out $OutputDirectory\$AllPublicKeysInChainOut -password pass:"
            $Process = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
            $stdout = $Process.StandardOutput.ReadToEnd()
            $stderr = $Process.StandardError.ReadToEnd()
            $AllOutput = $stdout + $stderr

            if ($AllOutput -match "error") {
                Write-Warning "openssl.exe reports that -PFXFilePwd is incorrect."
                throw
            }
        }
        catch {
            $PFXFilePwdFailure = $true
        }
    }
    if ($PFXFilePwdFailure -eq $true) {
        Write-Verbose "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
        Write-Error "The value for -PFXFilePwd is incorrect or was not supplied (and is needed). Halting!"
        $global:FunctionResult = "1"
        return
    }
    New-Variable -Name "CertObj$PFXFileNameSansExt" -Scope Script -Value $(
        [pscustomobject][ordered]@{
            CertName                = "$PFXFileNameSansExt`AllPublicKCertsInChain"
            AllCertInfo             = Get-Content "$OutputDirectory\$AllPublicKeysInChainOut"
            FileLocation            = "$OutputDirectory\$AllPublicKeysInChainOut"
        }
    ) -Force

    $ArrayOfPubCertPSObjects +=, $(Get-Variable -Name "CertObj$PFXFileNameSansExt" -ValueOnly)


    # Parse the Public Certificate Chain File and and Write Each Public Certificate to a Separate File
    # These files should have the EXACT SAME CONTENT as the .cer counterparts
    $PublicKeySansChainPrep1 = $(Get-Content "$OutputDirectory\$AllPublicKeysInChainOut") -join "`n"
    $PublicKeySansChainPrep2 = $($PublicKeySansChainPrep1 -replace "-----END CERTIFICATE-----","-----END CERTIFICATE-----;;;").Split(";;;")
    $PublicKeySansChainPrep3 = foreach ($obj1 in $PublicKeySansChainPrep2) {
        if ($obj1 -like "*[\w]*") {
            $obj1.Trim()
        }
    }
    # Setup PSObject for Certs with CertName and CertValue
    foreach ($obj1 in $PublicKeySansChainPrep3) {
        $CertNamePrep = $($obj1).Split("`n") | foreach {if ($_ | Select-String "subject") {$_}}
        $CertName = $($CertNamePrep | Select-String "CN=([\w]|[\W]){1,1000}$").Matches.Value -replace "CN=",""
        $IndexNumberForBeginCert = $obj1.Split("`n") | foreach {
            if ($_ -match "-----BEGIN CERTIFICATE-----") {
                [array]::indexof($($obj1.Split("`n")),$_)
            }
        }
        $IndexNumberForEndCert = $obj1.Split("`n") | foreach {
            if ($_ -match "-----End CERTIFICATE-----") {
                [array]::indexof($($obj1.Split("`n")),$_)
            }
        }
        $CertValue = $($($obj1.Split("`n"))[$IndexNumberForBeginCert..$IndexNumberForEndCert] | Out-String).Trim()
        $AttribFriendlyNamePrep = $obj1.Split("`n") | Select-String "friendlyName"
        if ($AttribFriendlyNamePrep) {
            $AttribFriendlyName = $($AttribFriendlyNamePrep.Line).Split(":")[-1].Trim()
        }
        $tmpFile = [IO.Path]::GetTempFileName()
        $CertValue.Trim() | Out-File $tmpFile -Encoding Ascii

        $CertDumpContent = certutil -dump $tmpfile

        $SubjectTypePrep = $CertDumpContent | Select-String -Pattern "Subject Type="
        if ($SubjectTypePrep) {
            $SubjectType = $SubjectTypePrep.Line.Split("=")[-1]
        }
        $RootCertFlag = $CertDumpContent | Select-String -Pattern "Subject matches issuer"
        
        if ($SubjectType -eq "CA" -and $RootCertFlag) {
            $RootCACert = $True
        }
        else {
            $RootCACert = $False
        }
        if ($SubjectType -eq "CA" -and !$RootCertFlag) {
            $IntermediateCACert = $True
        }
        else {
            $IntermediateCACert = $False
        }
        if ($RootCACert -eq $False -and $IntermediateCACert -eq $False) {
            $EndPointCert = $True
        }
        else {
            $EndPointCert = $False
        }

        New-Variable -Name "CertObj$CertName" -Scope Script -Value $(
            [pscustomobject][ordered]@{
                CertName                = $CertName
                FriendlyName            = $AttribFriendlyName
                CertValue               = $CertValue.Trim()
                AllCertInfo             = $obj1.Trim()
                RootCACert              = $RootCACert
                IntermediateCACert      = $IntermediateCACert
                EndPointCert            = $EndPointCert
                FileLocation            = "$OutputDirectory\$($CertName)_Public_Cert.pem"
            }
        ) -Force

        $ArrayOfPubCertPSObjects +=, $(Get-Variable -Name "CertObj$CertName" -ValueOnly)

        Remove-Item -Path $tmpFile -Force
        Remove-Variable -Name "tmpFile" -Force
    }

    # Write each CertValue to Separate Files (i.e. writing all public keys in chain to separate files)
    foreach ($obj1 in $ArrayOfPubCertPSObjects) {
        if ($(Test-Path $obj1.FileLocation) -and !$Force) {
            Write-Verbose "The extracted Public cert $($obj1.CertName) was NOT written to $OutputDirectory because it already exists there!"
        }
        if (!$(Test-Path $obj1.FileLocation) -or $Force) {
            $obj1.CertValue | Out-File "$($obj1.FileLocation)" -Encoding Ascii
            Write-Verbose "Public certs have been extracted and written to $OutputDirectory"
        }
    }

    New-Variable -Name "PubAndPrivInfoOutput" -Scope Script -Value $(
        [pscustomobject][ordered]@{
            PublicKeysInfo      = $ArrayOfPubCertPSObjects
            PrivateKeyInfo      = $(Get-Variable -Name "$PFXFileNameSansExt`PrivateKeyInfo" -ValueOnly)
        }
    ) -Force

    $(Get-Variable -Name "PubAndPrivInfoOutput" -ValueOnly)
    
    $global:FunctionResult = "0"
    ##### END Main Body #####

}


<#
    .SYNOPSIS
        This function creates a New Self-Signed Certificate meant to be used for DSC secret encryption and exports it to the
        specified directory.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER MachineName
        This parameter is MANDATORY.

        This parameter takes a string that represents the Subject Alternative Name (SAN) on the Self-Signed Certificate.

    .PARAMETER ExportDirectory
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to a directory that will contain the new Self-Signed Certificate.

    .EXAMPLE
        # Import the MiniLab Module and -

        PS C:\Users\zeroadmin> Get-EncryptionCert -CommonName "EncryptionCert" -ExportDirectory "$HOME\EncryptionCerts"

#>
function Get-EncryptionCert {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True)]
        [string]$CommonName,

        [Parameter(Mandatory=$True)]
        [string]$ExportDirectory
    )

    if (!$(Test-Path $ExportDirectory)) {
        Write-Error "The path '$ExportDirectory' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $CertificateFriendlyName = $CommonName
    $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {
        $_.FriendlyName -eq $CertificateFriendlyName
    } | Select-Object -First 1

    if (!$Cert) {
        $NewSelfSignedCertExSplatParams = @{
            Subject             = "CN=$CommonName"
            EKU                 = @('1.3.6.1.4.1.311.80.1','1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
            KeyUsage            = 'DigitalSignature, KeyEncipherment, DataEncipherment'
            SAN                 = $CommonName
            FriendlyName        = $CertificateFriendlyName
            Exportable          = $True
            StoreLocation       = 'LocalMachine'
            StoreName           = 'My'
            KeyLength           = 2048
            ProviderName        = 'Microsoft Enhanced Cryptographic Provider v1.0'
            AlgorithmName       = "RSA"
            SignatureAlgorithm  = "SHA256"
        }

        New-SelfsignedCertificateEx @NewSelfSignedCertExSplatParams

        # There is a slight delay before new cert shows up in Cert:
        # So wait for it to show.
        while (!$Cert) {
            $Cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object {$_.FriendlyName -eq $CertificateFriendlyName}
        }
    }

    #$null = Export-Certificate -Type CERT -Cert $Cert -FilePath "$ExportDirectory\$CommonName.cer"
    [System.IO.File]::WriteAllBytes("$ExportDirectory\$CommonName.cer", $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))

    [pscustomobject]@{
        CertFile        = Get-Item "$ExportDirectory\$CommonName.cer"
        CertInfo        = $Cert
    }
}


# Adds -password parameter to normal Get-PFXCertificate so that you can provide in advance and avoid prompt
function Get-PfxCertificateBetter {
    [CmdletBinding(DefaultParameterSetName='ByPath')]
    param(
        [Parameter(Position=0, Mandatory=$true, ParameterSetName='ByPath')] [string[]] $filePath,
        [Parameter(Mandatory=$true, ParameterSetName='ByLiteralPath')] [string[]] $literalPath,

        [Parameter(Position=1, ParameterSetName='ByPath')] 
        [Parameter(Position=1, ParameterSetName='ByLiteralPath')] [string] $password,

        [Parameter(Position=2, ParameterSetName='ByPath')]
        [Parameter(Position=2, ParameterSetName='ByLiteralPath')] [string] 
        [ValidateSet('DefaultKeySet','Exportable','MachineKeySet','PersistKeySet','UserKeySet','UserProtected')] $x509KeyStorageFlag = 'DefaultKeySet'
    )

    if($PsCmdlet.ParameterSetName -eq 'ByPath'){
        $literalPath = Resolve-Path $filePath 
    }

    if(!$password){
        # if the password parameter isn't present, just use the original cmdlet
        $cert = Get-PfxCertificate -literalPath $literalPath
    } else {
        # otherwise use the .NET implementation
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $cert.Import($literalPath, $password, $X509KeyStorageFlag)
    }

    return $cert
}


<#
    .SYNOPSIS
        If a System.Security.Cryptography.X509Certificates.X509Certificate2 object has properties...
            HasPrivateKey        : True
            PrivateKey           :
        ...and you would like to get the System.Security.Cryptography.RSACryptoServiceProvider object that should be in
        the PrivateKey property, use this function.

    .DESCRIPTION
        See SYNOPSIS

    .NOTES
        Depends on Extract-PfxCerts and therefore depends on openssl.exe.

        NOTE: Nothing needs to be installed in order to use openssl.exe.

        IMPORTANT NOTE REGARDING -CertObject PARAMETER:
        If you are getting the value for the -CertObject parameter from an already existing .pfx file (as opposed to the Cert Store),
        *DO NOT* use the Get-PFXCertificate cmdlet. The cmdlet does something strange that causes a misleading/incorrect error if the
        private key in the .pfx is password protected.

        Instead, use the following:
            $CertPwd = ConvertTo-SecureString -String 'RaNDompaSSwd123' -Force -AsPlainText
            $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        
        If you are getting the value for the -CertObject parameter from the Certificate Store, either of the following should be fine
            $CertObj = Get-ChildItem Cert:\LocalMachine\My\<Thumbprint>
            $CertObj = Get-ChildItem Cert:\CurrentUser\My\<Thumbprint>

        WARNING: This function defaults to temporarily writing the unprotected private key to its own file in -TempOutputDirectory.
        The parameter -CleanupOpenSSLOutputs is set to $true by default, so the unprotected private key will only exist on the file
        system for a couple seconds.  If you would like to keep the unprotected private key on the file system, set the
        -CleanupOpenSSLOutputs parameter to $false.

    .PARAMETER CertObject
        Mandatory.

        Must be a System.Security.Cryptography.X509Certificates.X509Certificate2 object.

        If you are getting the value for the -CertObject parameter from an already existing .pfx file (as opposed to the Cert Store),
        *DO NOT* use the Get-PFXCertificate cmdlet. The cmdlet does something strange that causes a misleading/incorrect error if the
        private key in the .pfx is password protected.

        Instead, use the following:
            $CertPwd = ConvertTo-SecureString -String 'RaNDompaSSwd123' -Force -AsPlainText
            $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        
        If you are getting the value for the -CertObject parameter from the Certificate Store, either of the following should be fine
            $CertObj = Get-ChildItem Cert:\LocalMachine\My\<Thumbprint>
            $CertObj = Get-ChildItem Cert:\CurrentUser\My\<Thumbprint>

    .PARAMETER TempOutputDirectory
        Mandatory.

        Must be a full path to a directory. Punlic certificates and the private key within the -CertObject will *temporarily*
        be written to this directory as a result of the helper function Extract-PfxCerts.

    .PARAMETER CertPwd
        Optional.

        This parameter must be a System.Security.SecureString.

        This parameter is Mandatory if the private key in the .pfx is password protected.

    .PARAMETER CleanupOpenSSLOutputs
        Optional.

        Must be Boolean.

        During this function, openssl.exe is used to extract all public certs and the private key from the -CertObject. Each of these
        certs and the key are written to separate files in -TempOutputDirectory. This parameter removes these file outputs at the
        conclusion of the function. This parameter is set to $true by default.

    .EXAMPLE
        # If the private key in the .pfx is password protected...
        PS C:\Users\zeroadmin> $CertPwd = Read-Host -Prompt "Please enter the Certificate's Private Key password" -AsSecureString
        Please enter the Certificate's Private Key password: ***************
        PS C:\Users\zeroadmin> $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $CertPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout" -CertPwd $CertPwd

    .EXAMPLE
        # If the private key in the .pfx is NOT password protected...
        PS C:\Users\zeroadmin> $CertObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new("$HOME\Desktop\testcert7.pfx", $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout"

    .EXAMPLE
        # Getting -CertObject from the Certificate Store where private key is password protected...
        PS C:\Users\zeroadmin> $CertPwd = Read-Host -Prompt "Please enter the Certificate's Private Key password" -AsSecureString
        Please enter the Certificate's Private Key password: ***************
        PS C:\Users\zeroadmin> $CertObj = Get-ChildItem "Cert:\LocalMachine\My\5359DDD9CB88873DF86617EC28FAFADA17112AE6"
        PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout" -CertPwd $CertPwd

    .EXAMPLE
        # Getting -CertObject from the Certificate Store where private key is NOT password protected...
        PS C:\Users\zeroadmin> $CertObj = Get-ChildItem "Cert:\LocalMachine\My\5359DDD9CB88873DF86617EC28FAFADA17112AE6"
        PS C:\Users\zeroadmin> Get-PrivateKeyProperty -CertObject $CertObj -TempOutputDirectory "$HOME\tempout"
#>
function Get-PrivateKeyProperty {
    [CmdletBinding()]
    Param( 
        [Parameter(Mandatory=$True)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$CertObject,

        [Parameter(Mandatory=$True)]
        $TempOutputDirectory = $(Read-Host -Prompt "Please enter the full path to the directory where all output files will be written"),

        [Parameter(Mandatory=$False)]
        [securestring]$CertPwd,

        [Parameter(Mandatory=$False)]
        [bool]$CleanupOpenSSLOutputs = $true,

        [Parameter(Mandatory=$False)]
        [switch]$DownloadAndAddOpenSSLToPath

    )

    ##### BEGIN Variable/Parameter Transforms and PreRun Prep #####

    if ($CertObject.PrivateKey -eq $null -and $CertObject.HasPrivateKey -eq $false -or $CertObject.HasPrivateKey -ne $true) {
        Write-Verbose "There is no Private Key associated with this System.Security.Cryptography.X509Certificates.X509Certificate2 object (for real though)! Halting!"
        Write-Error "There is no Private Key associated with this System.Security.Cryptography.X509Certificates.X509Certificate2 object (for real though)! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if (! $(Get-Command openssl.exe -ErrorAction SilentlyContinue)) {
        if (!$DownloadAndAddOpenSSLToPath) {
            Write-Verbose "The Helper Function Extract-PFXCerts requires openssl.exe. Openssl.exe cannot be found on this machine. Use the -DownloadAndAddOpenSSLToPath parameter to download openssl.exe and add it to `$env:Path. NOTE: Openssl.exe does NOT require installation. Halting!"
            Write-Error "The Helper Function Extract-PFXCerts requires openssl.exe. Openssl.exe cannot be found on this machine. Use the -DownloadAndAddOpenSSLToPath parameter to download openssl.exe and add it to `$env:Path. NOTE: Openssl.exe does NOT require installation. Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $CertName = $($CertObject.Subject | Select-String -Pattern "^CN=[\w]+").Matches.Value -replace "CN=",""
    try {
        $pfxbytes = $CertObject.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx)
        [System.IO.File]::WriteAllBytes("$TempOutputDirectory\$CertName.pfx", $pfxbytes)
    }
    catch {
        Write-Warning "Either the Private Key is Password Protected or it is marked as Unexportable...Trying to import `$CertObject to Cert:\LocalMachine\My Store..."
        # NOTE: The $CertObject.Export() method in the above try block has a second argument for PlainTextPassword, but it doesn't seem to work consistently
        
        # Check to see if it's already in the Cert:\LocalMachine\My Store
        if ($(Get-Childitem "Cert:\LocalMachine\My").Thumbprint -contains $CertObject.Thumbprint) {
            Write-Host "The certificate $CertName is already in the Cert:\LocalMachine\My Store."
        }
        else {
            Write-Host "Importing $CertName to Cert:\LocalMachine\My Store..."
            $X509Store = [System.Security.Cryptography.X509Certificates.X509Store]::new([System.Security.Cryptography.X509Certificates.StoreName]::My, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
            $X509Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $X509Store.Add($CertObject)
        }

        Write-Host "Attempting to export `$CertObject from Cert:\LocalMachine\My Store to .pfx file..."

        if (!$CertPwd) {
            $CertPwd = Read-Host -Prompt "Please enter the password for the private key in the certificate $CertName" -AsSecureString
        }

        $CertItem = Get-Item "Cert:\LocalMachine\My\$($CertObject.Thumbprint)"
        [System.IO.File]::WriteAllBytes("$TempOutputDirectory\$CertName.pfx", $CertItem.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $CertPwd))
        #Export-PfxCertificate -FilePath "$TempOutputDirectory\$CertName.pfx" -Cert "Cert:\LocalMachine\My\$($CertObject.Thumbprint)" -Password $CertPwd

    }

    # NOTE: If openssl.exe isn't already available, the Extract-PFXCerts function downloads it and adds it to $env:Path
    if ($CertPwd) {
        $global:PubCertAndPrivKeyInfo = Extract-PFXCerts -PFXFilePath "$TempOutputDirectory\$CertName.pfx" -PFXFilePwd $CertPwd -OutputDirectory "$TempOutputDirectory" -DownloadAndAddOpenSSLToPath
    }
    else {
        $global:PubCertAndPrivKeyInfo = Extract-PFXCerts -PFXFilePath "$TempOutputDirectory\$CertName.pfx" -OutputDirectory "$TempOutputDirectory" -DownloadAndAddOpenSSLToPath
    }

    ##### END Variable/Parameter Transforms and PreRun Prep #####


    ##### BEGIN Main Body #####

    if ($global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath -eq $null) {
        # Strip Private Key of Password
        $UnProtectedPrivateKeyOut = "$($(Get-ChildItem $PathToCertFile).BaseName)"+"_unprotected_private_key"+".pem"
        & openssl.exe rsa -in $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.ProtectedPrivateKeyFilePath -out "$HOME\$UnProtectedPrivateKeyOut" 2>&1 | Out-Null
        $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath = "$HOME\$UnProtectedPrivateKeyOut"
    }

    #Write-Host "Loading opensslkey.cs from https://github.com/sushihangover/SushiHangover-PowerShell/blob/master/modules/SushiHangover-RSACrypto/opensslkey.cs"
    #$opensslkeysource = $(Invoke-WebRequest -Uri "https://raw.githubusercontent.com/sushihangover/SushiHangover-PowerShell/master/modules/SushiHangover-RSACrypto/opensslkey.cs").Content
    try {
        Add-Type -TypeDefinition $opensslkeysource
    }
    catch {
        if ($_.Exception -match "already exists") {
            Write-Verbose "The JavaScience.Win32 assembly (i.e. opensslkey.cs) is already loaded. Continuing..."
        }
    }
    $PemText = [System.IO.File]::ReadAllText($global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath)
    $PemPrivateKey = [javascience.opensslkey]::DecodeOpenSSLPrivateKey($PemText)
    [System.Security.Cryptography.RSACryptoServiceProvider]$RSA = [javascience.opensslkey]::DecodeRSAPrivateKey($PemPrivateKey)
    $RSA

    # Cleanup
    if ($CleanupOpenSSLOutputs) {
        $ItemsToRemove = @(
            $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.ProtectedPrivateKeyFilePath
            $global:PubCertAndPrivKeyInfo.PrivateKeyInfo.UnProtectedPrivateKeyFilePath
        ) + $global:PubCertAndPrivKeyInfo.PublicKeysInfo.FileLocation

        foreach ($item in $ItemsToRemove) {
            Remove-Item $item
        }
    }

    ##### END Main Body #####

}


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


<#
    .Synopsis
        This cmdlet generates a self-signed certificate.
    .Description
        This cmdlet generates a self-signed certificate with the required data.
    .NOTES
        New-SelfSignedCertificateEx.ps1
        Version 1.0
        
        Creates self-signed certificate. This tool is a base replacement
        for deprecated makecert.exe
        
        Vadims Podans (c) 2013
        http://en-us.sysadmins.lv/

    .Parameter Subject
        Specifies the certificate subject in a X500 distinguished name format.
        Example: CN=Test Cert, OU=Sandbox
    .Parameter NotBefore
        Specifies the date and time when the certificate become valid. By default previous day
        date is used.
    .Parameter NotAfter
        Specifies the date and time when the certificate expires. By default, the certificate is
        valid for 1 year.
    .Parameter SerialNumber
        Specifies the desired serial number in a hex format.
        Example: 01a4ff2
    .Parameter ProviderName
        Specifies the Cryptography Service Provider (CSP) name. You can use either legacy CSP
        and Key Storage Providers (KSP). By default "Microsoft Enhanced Cryptographic Provider v1.0"
        CSP is used.
    .Parameter AlgorithmName
        Specifies the public key algorithm. By default RSA algorithm is used. RSA is the only
        algorithm supported by legacy CSPs. With key storage providers (KSP) you can use CNG
        algorithms, like ECDH. For CNG algorithms you must use full name:
        ECDH_P256
        ECDH_P384
        ECDH_P521
        
        In addition, KeyLength parameter must be specified explicitly when non-RSA algorithm is used.
    .Parameter KeyLength
        Specifies the key length to generate. By default 2048-bit key is generated.
    .Parameter KeySpec
        Specifies the public key operations type. The possible values are: Exchange and Signature.
        Default value is Exchange.
    .Parameter EnhancedKeyUsage
        Specifies the intended uses of the public key contained in a certificate. You can
        specify either, EKU friendly name (for example 'Server Authentication') or
        object identifier (OID) value (for example '1.3.6.1.5.5.7.3.1').
    .Parameter KeyUsage
        Specifies restrictions on the operations that can be performed by the public key contained in the certificate.
        Possible values (and their respective integer values to make bitwise operations) are:
        EncipherOnly
        CrlSign
        KeyCertSign
        KeyAgreement
        DataEncipherment
        KeyEncipherment
        NonRepudiation
        DigitalSignature
        DecipherOnly
        
        you can combine key usages values by using bitwise OR operation. when combining multiple
        flags, they must be enclosed in quotes and separated by a comma character. For example,
        to combine KeyEncipherment and DigitalSignature flags you should type:
        "KeyEncipherment, DigitalSignature".
        
        If the certificate is CA certificate (see IsCA parameter), key usages extension is generated
        automatically with the following key usages: Certificate Signing, Off-line CRL Signing, CRL Signing.
    .Parameter SubjectAlternativeName
        Specifies alternative names for the subject. Unlike Subject field, this extension
        allows to specify more than one name. Also, multiple types of alternative names
        are supported. The cmdlet supports the following SAN types:
        RFC822 Name
        IP address (both, IPv4 and IPv6)
        Guid
        Directory name
        DNS name
    .Parameter IsCA
        Specifies whether the certificate is CA (IsCA = $true) or end entity (IsCA = $false)
        certificate. If this parameter is set to $false, PathLength parameter is ignored.
        Basic Constraints extension is marked as critical.
    .Parameter PathLength
        Specifies the number of additional CA certificates in the chain under this certificate. If
        PathLength parameter is set to zero, then no additional (subordinate) CA certificates are
        permitted under this CA.
    .Parameter CustomExtension
        Specifies the custom extension to include to a self-signed certificate. This parameter
        must not be used to specify the extension that is supported via other parameters. In order
        to use this parameter, the extension must be formed in a collection of initialized
        System.Security.Cryptography.X509Certificates.X509Extension objects.
    .Parameter SignatureAlgorithm
        Specifies signature algorithm used to sign the certificate. By default 'SHA1'
        algorithm is used.
    .Parameter FriendlyName
        Specifies friendly name for the certificate.
    .Parameter StoreLocation
        Specifies the store location to store self-signed certificate. Possible values are:
        'CurrentUser' and 'LocalMachine'. 'CurrentUser' store is intended for user certificates
        and computer (as well as CA) certificates must be stored in 'LocalMachine' store.
    .Parameter StoreName
        Specifies the container name in the certificate store. Possible container names are:
        AddressBook
        AuthRoot
        CertificateAuthority
        Disallowed
        My
        Root
        TrustedPeople
        TrustedPublisher
    .Parameter Path
        Specifies the path to a PFX file to export a self-signed certificate.
    .Parameter Password
        Specifies the password for PFX file.
    .Parameter AllowSMIME
        Enables Secure/Multipurpose Internet Mail Extensions for the certificate.
    .Parameter Exportable
        Marks private key as exportable. Smart card providers usually do not allow
        exportable keys.
 .Example
  # Creates a self-signed certificate intended for code signing and which is valid for 5 years. Certificate
  # is saved in the Personal store of the current user account.
  
        New-SelfsignedCertificateEx -Subject "CN=Test Code Signing" -EKU "Code Signing" -KeySpec "Signature" `
        -KeyUsage "DigitalSignature" -FriendlyName "Test code signing" -NotAfter [datetime]::now.AddYears(5)
        
        
    .Example
  # Creates a self-signed SSL certificate with multiple subject names and saves it to a file. Additionally, the
        # certificate is saved in the Personal store of the Local Machine store. Private key is marked as exportable,
        # so you can export the certificate with a associated private key to a file at any time. The certificate
  # includes SMIME capabilities.
  
  New-SelfsignedCertificateEx -Subject "CN=www.domain.com" -EKU "Server Authentication", "Client authentication" `
        -KeyUsage "KeyEcipherment, DigitalSignature" -SAN "sub.domain.com","www.domain.com","192.168.1.1" `
        -AllowSMIME -Path C:\test\ssl.pfx -Password (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force) -Exportable `
        -StoreLocation "LocalMachine"
        
    .Example
  # Creates a self-signed SSL certificate with multiple subject names and saves it to a file. Additionally, the
        # certificate is saved in the Personal store of the Local Machine store. Private key is marked as exportable,
        # so you can export the certificate with a associated private key to a file at any time. Certificate uses
        # Ellyptic Curve Cryptography (ECC) key algorithm ECDH with 256-bit key. The certificate is signed by using
  # SHA256 algorithm.
  
  New-SelfsignedCertificateEx -Subject "CN=www.domain.com" -EKU "Server Authentication", "Client authentication" `
        -KeyUsage "KeyEcipherment, DigitalSignature" -SAN "sub.domain.com","www.domain.com","192.168.1.1" `
        -StoreLocation "LocalMachine" -ProviderName "Microsoft Software Key Storae Provider" -AlgorithmName ecdh_256 `
  -KeyLength 256 -SignatureAlgorithm sha256
  
    .Example
  # Creates self-signed root CA certificate.

  New-SelfsignedCertificateEx -Subject "CN=Test Root CA, OU=Sandbox" -IsCA $true -ProviderName `
  "Microsoft Software Key Storage Provider" -Exportable
  
#>
function New-SelfSignedCertificateEx {
    [CmdletBinding(DefaultParameterSetName = '__store')]
 param (
  [Parameter(Mandatory = $true, Position = 0)]
  [string]$Subject,
  [Parameter(Position = 1)]
  [datetime]$NotBefore = [DateTime]::Now.AddDays(-1),
  [Parameter(Position = 2)]
  [datetime]$NotAfter = $NotBefore.AddDays(365),
  [string]$SerialNumber,
  [Alias('CSP')]
  [string]$ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0",
  [string]$AlgorithmName = "RSA",
  [int]$KeyLength = 2048,
  [validateSet("Exchange","Signature")]
  [string]$KeySpec = "Exchange",
  [Alias('EKU')]
  [Security.Cryptography.Oid[]]$EnhancedKeyUsage,
  [Alias('KU')]
  [Security.Cryptography.X509Certificates.X509KeyUsageFlags]$KeyUsage,
  [Alias('SAN')]
  [String[]]$SubjectAlternativeName,
  [bool]$IsCA,
  [int]$PathLength = -1,
  [Security.Cryptography.X509Certificates.X509ExtensionCollection]$CustomExtension,
  [ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
  [string]$SignatureAlgorithm = "SHA1",
  [string]$FriendlyName,
  [Parameter(ParameterSetName = '__store')]
  [Security.Cryptography.X509Certificates.StoreLocation]$StoreLocation = "CurrentUser",
  [Parameter(ParameterSetName = '__store')]
  [Security.Cryptography.X509Certificates.StoreName]$StoreName = "My",
  [Parameter(Mandatory = $true, ParameterSetName = '__file')]
  [Alias('OutFile','OutPath','Out')]
  [IO.FileInfo]$Path,
  [Parameter(Mandatory = $true, ParameterSetName = '__file')]
  [Security.SecureString]$Password,
  [switch]$AllowSMIME,
  [switch]$Exportable
 )

 $ErrorActionPreference = "Stop"
 if ([Environment]::OSVersion.Version.Major -lt 6) {
  $NotSupported = New-Object NotSupportedException -ArgumentList "Windows XP and Windows Server 2003 are not supported!"
  throw $NotSupported
 }
 $ExtensionsToAdd = @()

    #region >> Constants
 # contexts
 New-Variable -Name UserContext -Value 0x1 -Option Constant
 New-Variable -Name MachineContext -Value 0x2 -Option Constant
 # encoding
 New-Variable -Name Base64Header -Value 0x0 -Option Constant
 New-Variable -Name Base64 -Value 0x1 -Option Constant
 New-Variable -Name Binary -Value 0x3 -Option Constant
 New-Variable -Name Base64RequestHeader -Value 0x4 -Option Constant
 # SANs
 New-Variable -Name OtherName -Value 0x1 -Option Constant
 New-Variable -Name RFC822Name -Value 0x2 -Option Constant
 New-Variable -Name DNSName -Value 0x3 -Option Constant
 New-Variable -Name DirectoryName -Value 0x5 -Option Constant
 New-Variable -Name URL -Value 0x7 -Option Constant
 New-Variable -Name IPAddress -Value 0x8 -Option Constant
 New-Variable -Name RegisteredID -Value 0x9 -Option Constant
 New-Variable -Name Guid -Value 0xa -Option Constant
 New-Variable -Name UPN -Value 0xb -Option Constant
 # installation options
 New-Variable -Name AllowNone -Value 0x0 -Option Constant
 New-Variable -Name AllowNoOutstandingRequest -Value 0x1 -Option Constant
 New-Variable -Name AllowUntrustedCertificate -Value 0x2 -Option Constant
 New-Variable -Name AllowUntrustedRoot -Value 0x4 -Option Constant
 # PFX export options
 New-Variable -Name PFXExportEEOnly -Value 0x0 -Option Constant
 New-Variable -Name PFXExportChainNoRoot -Value 0x1 -Option Constant
 New-Variable -Name PFXExportChainWithRoot -Value 0x2 -Option Constant
    #endregion >> Constants
 
    #region >> Subject Processing
 # http://msdn.microsoft.com/en-us/library/aa377051(VS.85).aspx
 $SubjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
 $SubjectDN.Encode($Subject, 0x0)
    #endregion >> Subject Processing

    #region >> Extensions

    #region >> Enhanced Key Usages Processing
 if ($EnhancedKeyUsage) {
  $OIDs = New-Object -ComObject X509Enrollment.CObjectIDs
  $EnhancedKeyUsage | %{
   $OID = New-Object -ComObject X509Enrollment.CObjectID
   $OID.InitializeFromValue($_.Value)
   # http://msdn.microsoft.com/en-us/library/aa376785(VS.85).aspx
   $OIDs.Add($OID)
  }
  # http://msdn.microsoft.com/en-us/library/aa378132(VS.85).aspx
  $EKU = New-Object -ComObject X509Enrollment.CX509ExtensionEnhancedKeyUsage
  $EKU.InitializeEncode($OIDs)
  $ExtensionsToAdd += "EKU"
 }
    #endregion >> Enhanced Key Usages Processing

    #region >> Key Usages Processing
 if ($KeyUsage -ne $null) {
  $KU = New-Object -ComObject X509Enrollment.CX509ExtensionKeyUsage
  $KU.InitializeEncode([int]$KeyUsage)
  $KU.Critical = $true
  $ExtensionsToAdd += "KU"
 }
    #endregion >> Key Usages Processing

    #region >> Basic Constraints Processing
 if ($PSBoundParameters.Keys.Contains("IsCA")) {
  # http://msdn.microsoft.com/en-us/library/aa378108(v=vs.85).aspx
  $BasicConstraints = New-Object -ComObject X509Enrollment.CX509ExtensionBasicConstraints
  if (!$IsCA) {$PathLength = -1}
  $BasicConstraints.InitializeEncode($IsCA,$PathLength)
  $BasicConstraints.Critical = $IsCA
  $ExtensionsToAdd += "BasicConstraints"
 }
    #endregion >> Basic Constraints Processing

    #region >> SAN Processing
 if ($SubjectAlternativeName) {
  $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
  $Names = New-Object -ComObject X509Enrollment.CAlternativeNames
  foreach ($altname in $SubjectAlternativeName) {
   $Name = New-Object -ComObject X509Enrollment.CAlternativeName
   if ($altname.Contains("@")) {
    $Name.InitializeFromString($RFC822Name,$altname)
   } else {
    try {
     $Bytes = [Net.IPAddress]::Parse($altname).GetAddressBytes()
     $Name.InitializeFromRawData($IPAddress,$Base64,[Convert]::ToBase64String($Bytes))
    } catch {
     try {
      $Bytes = [Guid]::Parse($altname).ToByteArray()
      $Name.InitializeFromRawData($Guid,$Base64,[Convert]::ToBase64String($Bytes))
     } catch {
      try {
       $Bytes = ([Security.Cryptography.X509Certificates.X500DistinguishedName]$altname).RawData
       $Name.InitializeFromRawData($DirectoryName,$Base64,[Convert]::ToBase64String($Bytes))
      } catch {$Name.InitializeFromString($DNSName,$altname)}
     }
    }
   }
   $Names.Add($Name)
  }
  $SAN.InitializeEncode($Names)
  $ExtensionsToAdd += "SAN"
 }
    #endregion >> SAN Processing

    #region >> Custom Extensions
 if ($CustomExtension) {
  $count = 0
  foreach ($ext in $CustomExtension) {
   # http://msdn.microsoft.com/en-us/library/aa378077(v=vs.85).aspx
   $Extension = New-Object -ComObject X509Enrollment.CX509Extension
   $EOID = New-Object -ComObject X509Enrollment.CObjectId
   $EOID.InitializeFromValue($ext.Oid.Value)
   $EValue = [Convert]::ToBase64String($ext.RawData)
   $Extension.Initialize($EOID,$Base64,$EValue)
   $Extension.Critical = $ext.Critical
   New-Variable -Name ("ext" + $count) -Value $Extension
   $ExtensionsToAdd += ("ext" + $count)
   $count++
  }
 }
    #endregion >> Custom Extensions

    #endregion >> Extensions

    #region >> Private Key
 # http://msdn.microsoft.com/en-us/library/aa378921(VS.85).aspx
 $PrivateKey = New-Object -ComObject X509Enrollment.CX509PrivateKey
 $PrivateKey.ProviderName = $ProviderName
 $AlgID = New-Object -ComObject X509Enrollment.CObjectId
 $AlgID.InitializeFromValue(([Security.Cryptography.Oid]$AlgorithmName).Value)
 $PrivateKey.Algorithm = $AlgID
 # http://msdn.microsoft.com/en-us/library/aa379409(VS.85).aspx
 $PrivateKey.KeySpec = switch ($KeySpec) {"Exchange" {1}; "Signature" {2}}
 $PrivateKey.Length = $KeyLength
 # key will be stored in current user certificate store
 switch ($PSCmdlet.ParameterSetName) {
  '__store' {
   $PrivateKey.MachineContext = if ($StoreLocation -eq "LocalMachine") {$true} else {$false}
  }
  '__file' {
   $PrivateKey.MachineContext = $false
  }
 }
 $PrivateKey.ExportPolicy = if ($Exportable) {1} else {0}
 $PrivateKey.Create()
    #endregion >> Private Key

 # http://msdn.microsoft.com/en-us/library/aa377124(VS.85).aspx
 $Cert = New-Object -ComObject X509Enrollment.CX509CertificateRequestCertificate
 if ($PrivateKey.MachineContext) {
  $Cert.InitializeFromPrivateKey($MachineContext,$PrivateKey,"")
 } else {
  $Cert.InitializeFromPrivateKey($UserContext,$PrivateKey,"")
 }
 $Cert.Subject = $SubjectDN
 $Cert.Issuer = $Cert.Subject
 $Cert.NotBefore = $NotBefore
 $Cert.NotAfter = $NotAfter
 foreach ($item in $ExtensionsToAdd) {$Cert.X509Extensions.Add((Get-Variable -Name $item -ValueOnly))}
 if (![string]::IsNullOrEmpty($SerialNumber)) {
  if ($SerialNumber -match "[^0-9a-fA-F]") {throw "Invalid serial number specified."}
  if ($SerialNumber.Length % 2) {$SerialNumber = "0" + $SerialNumber}
  $Bytes = $SerialNumber -split "(.{2})" | ?{$_} | %{[Convert]::ToByte($_,16)}
  $ByteString = [Convert]::ToBase64String($Bytes)
  $Cert.SerialNumber.InvokeSet($ByteString,1)
 }
 if ($AllowSMIME) {$Cert.SmimeCapabilities = $true}
 $SigOID = New-Object -ComObject X509Enrollment.CObjectId
 $SigOID.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)
 $Cert.SignatureInformation.HashAlgorithm = $SigOID
 # completing certificate request template building
 $Cert.Encode()
 
 # interface: http://msdn.microsoft.com/en-us/library/aa377809(VS.85).aspx
 $Request = New-Object -ComObject X509Enrollment.CX509enrollment
 $Request.InitializeFromRequest($Cert)
 $Request.CertificateFriendlyName = $FriendlyName
 $endCert = $Request.CreateRequest($Base64)
 $Request.InstallResponse($AllowUntrustedCertificate,$endCert,$Base64,"")
 switch ($PSCmdlet.ParameterSetName) {
  '__file' {
   $PFXString = $Request.CreatePFX(
    [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)),
    $PFXExportEEOnly,
    $Base64
   )
   Set-Content -Path $Path -Value ([Convert]::FromBase64String($PFXString)) -Encoding Byte
  }
 }
}


if (Test-Path "$PSScriptRoot\VariableLibrary.ps1") {
    . "$PSScriptRoot\VariableLibrary.ps1"
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUINXF5PY3fhLt4AZCA1JdgTeh
# 3+ygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKbHpXk6tW1ZHHsK
# bB82FdwKu0ElMA0GCSqGSIb3DQEBAQUABIIBALsVv5TlUg3oW9MjrlwnwVChNgnO
# I1Bj7UMl09H241Pn+eU96spqTQhtBhEL9c8JVAB15aqZ5OgDeAnW6E8Z75owoCH/
# DlpOfSyrpx/1wgKaYcly+3hBvtGITHJkZxb2w2f2SHUr3IRPYORACi50JM7eXbPn
# Ppbxej7R6xR4w3tzyWqkdpQCaw6+PRerEBT/UMbnIiWNzEa7ejG6UNxo27kIqUFm
# dLMInIalo0BlzuKRb+HIfJDz93zDmkEMO5bvBvvjZaZwUTrXeafQCx1nGuyf0AqO
# U16asDXRTnrvpfS7L+ra5lvv138CVdzo/FLjnBDSqNyezeRRkXd/sT3okd0=
# SIG # End signature block
