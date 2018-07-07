[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/=master&svg=true)](https://ci.appveyor.com/project/pldmgg/encryptdecrypt/branch/master)


# EncryptDecrypt
Create AES/RSA encrypted strings or files. Decrypt existing AES/RSA encrypted strings or files.

Compatible with Windows PowerShell 5.1 and PowerShell Core 6.X (on Windows)

## Getting Started

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the EncryptDecrypt folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module EncryptDecrypt

# Import the module.
    Import-Module EncryptDecrypt    # Alternatively, Import-Module <PathToModuleFolder>

# Get commands in the module
    Get-Command -Module EncryptDecrypt

# Get help
    Get-Help <EncryptDecrypt Function> -Full
    Get-Help about_EncryptDecrypt
```

## Examples

### Scenario 1: Encrypt/Decrypt a String

```powershell
PS C:\Users\zeroadmin> New-EncryptedFile -SourceType String -ContentToEncrypt 'thisIsMySecret' -CNOfNewCert "String1" -FileToOutput "$HOME\Downloads\StringTest.txt"


FileEncryptedViaRSA                : C:\Users\zeroadmin\Downloads\StringTest.txt.rsaencrypted
FileEncryptedViaAES                :
OriginalFile                       :
CertficateUsedForRSAEncryption     : [Subject]
                                       CN=String1

                                     [Issuer]
                                       CN=String1

                                     [Serial Number]
                                       478497203AA0E29B4A6C63B6DFC9EED7

                                     [Not Before]
                                       7/6/2018 2:35:55 PM

                                     [Not After]
                                       7/6/2019 2:35:55 PM

                                     [Thumbprint]
                                       D5567CADE3D49F148A3EF82C42F1781EFBACA5E9

LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My\D5567CADE3D49F148A3EF82C42F1781EFBACA5E9
UnprotectedAESKey                  :
RSAEncryptedAESKey                 :
RSAEncryptedAESKeyLocation         :
AllFileOutputs                     : {C:\Users\zeroadmin\Downloads\StringTest.txt.rsaencrypted, C:\Users\zeroadmin\Downloads\String1.pfx}

PS C:\Users\zeroadmin> Get-DecryptedContent -SourceType File -ContentToDecrypt "$HOME\Downloads\StringTest.txt.rsaencrypted" -PathToPfxFile "$HOME\Downloads\String1.pfx"
Doing RSA Decryption


DecryptedFiles                     : C:\Users\zeroadmin\Downloads\StringTest.txt.rsaencrypted.decrypted
FailedToDecryptFiles               : {}
CertUsedDuringDecryption           : [Subject]
                                       CN=String1

                                     [Issuer]
                                       CN=String1

                                     [Serial Number]
                                       478497203AA0E29B4A6C63B6DFC9EED7

                                     [Not Before]
                                       7/6/2018 2:35:55 PM

                                     [Not After]
                                       7/6/2019 2:35:55 PM

                                     [Thumbprint]
                                       D5567CADE3D49F148A3EF82C42F1781EFBACA5E9

PFXCertUsedForPrivateKeyExtraction :
LocationOfCertUsedDuringDecryption : C:\Users\zeroadmin\Downloads\String1.pfx
UnprotectedAESKey                  :
LocationOfAESKey                   :
AllFileOutputs                     : C:\Users\zeroadmin\Downloads\StringTest.txt.rsaencrypted.decrypted
DecryptedContent                   : thisIsMySecret
```

### Scenario 2: Encrypt/Decrypt an Array Of Strings

```powershell
PS C:\Users\zeroadmin> New-EncryptedFile -SourceType ArrayOfStrings -ContentToEncrypt @("apple","pair","bananna") -FileToOutput "$HOME\Downloads\ArrayOfStrings1.txt"


FilesEncryptedViaRSA               : {C:\Users\zeroadmin\Downloads\ArrayOfStrings1_0.txt.rsaencrypted,
                                     C:\Users\zeroadmin\Downloads\ArrayOfStrings1_1.txt.rsaencrypted,
                                     C:\Users\zeroadmin\Downloads\ArrayOfStrings1_2.txt.rsaencrypted}
FilesEncryptedViaAES               :
OriginalFiles                      :
CertficateUsedForRSAEncryption     : [Subject]
                                       CN=ArrayOfStrings1

                                     [Issuer]
                                       CN=ArrayOfStrings1

                                     [Serial Number]
                                       354E9145B0C4969E4A661D878B8B977B

                                     [Not Before]
                                       7/6/2018 2:33:58 PM

                                     [Not After]
                                       7/6/2019 2:33:58 PM

                                     [Thumbprint]
                                       A4FFC78FF2856EEDF4F09FB75A0AEEC2D878622F

LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My\A4FFC78FF2856EEDF4F09FB75A0AEEC2D878622F
UnprotectedAESKey                  :
RSAEncryptedAESKey                 :
RSAEncryptedAESKeyLocation         :
AllFileOutputs                     : {C:\Users\zeroadmin\Downloads\ArrayOfStrings1_0.txt.rsaencrypted
                                     C:\Users\zeroadmin\Downloads\ArrayOfStrings1_1.txt.rsaencrypted
                                     C:\Users\zeroadmin\Downloads\ArrayOfStrings1_2.txt.rsaencrypted,
                                     C:\Users\zeroadmin\Downloads\ArrayOfStrings1.pfx}

PS C:\Users\zeroadmin> Get-DecryptedContent -SourceType File -ContentToDecrypt "$HOME\Downloads\ArrayOfStrings1_0.txt.rsaencrypted" -PathToPfxFile "$HOME\Downloads\ArrayOfStrings1.pfx"
Doing RSA Decryption


DecryptedFiles                     : C:\Users\zeroadmin\Downloads\ArrayOfStrings1_0.txt.rsaencrypted.decrypted
FailedToDecryptFiles               : {}
CertUsedDuringDecryption           : [Subject]
                                       CN=ArrayOfStrings1

                                     [Issuer]
                                       CN=ArrayOfStrings1

                                     [Serial Number]
                                       354E9145B0C4969E4A661D878B8B977B

                                     [Not Before]
                                       7/6/2018 2:33:58 PM

                                     [Not After]
                                       7/6/2019 2:33:58 PM

                                     [Thumbprint]
                                       A4FFC78FF2856EEDF4F09FB75A0AEEC2D878622F

PFXCertUsedForPrivateKeyExtraction :
LocationOfCertUsedDuringDecryption : C:\Users\zeroadmin\Downloads\ArrayOfStrings1.pfx
UnprotectedAESKey                  :
LocationOfAESKey                   :
AllFileOutputs                     : C:\Users\zeroadmin\Downloads\ArrayOfStrings1_0.txt.rsaencrypted.decrypted
DecryptedContent                   : apple
```

### Scenario 3: Encrypt/Decrypt a Small File

IMPORTANT NOTE: If a file is small enough in size, RSA Encryption/Decryption will be used.

```powershell
PS C:\Users\zeroadmin> New-EncryptedFile -SourceType File -ContentToEncrypt "C:\Users\zeroadmin\Downloads\SmallContent1.txt" -CNOfNewCert "SmallContent1"


FileEncryptedViaRSA                : C:\Users\zeroadmin\Downloads\SmallContent1.txt.rsaencrypted
FileEncryptedViaAES                :
OriginalFile                       : C:\Users\zeroadmin\Downloads\SmallContent1.txt.original
CertficateUsedForRSAEncryption     : [Subject]
                                       CN=SmallContent1

                                     [Issuer]
                                       CN=SmallContent1

                                     [Serial Number]
                                       27CBDE483839CEAB4769C2E256084527

                                     [Not Before]
                                       7/6/2018 2:55:25 PM

                                     [Not After]
                                       7/6/2019 2:55:25 PM

                                     [Thumbprint]
                                       580F4AD5AAEFEEF5428981109ED81F5F56E6624F

LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My\580F4AD5AAEFEEF5428981109ED81F5F56E6624F
UnprotectedAESKey                  :
RSAEncryptedAESKey                 :
RSAEncryptedAESKeyLocation         :
AllFileOutputs                     : {C:\Users\zeroadmin\Downloads\SmallContent1.txt.rsaencrypted, C:\Users\zeroadmin\Downloads\SmallContent1.txt.original,
                                     C:\Users\zeroadmin\Downloads\SmallContent1.pfx}

PS C:\Users\zeroadmin> Get-DecryptedContent -SourceType File -ContentToDecrypt "C:\Users\zeroadmin\Downloads\SmallContent1.txt.rsaencrypted" -PathToPfxFile "C:\Users\zeroadmin\Downloads\SmallContent1.pfx"
Doing RSA Decryption


DecryptedFiles                     : C:\Users\zeroadmin\Downloads\SmallContent1.txt.rsaencrypted.decrypted
FailedToDecryptFiles               : {}
CertUsedDuringDecryption           : [Subject]
                                       CN=SmallContent1

                                     [Issuer]
                                       CN=SmallContent1

                                     [Serial Number]
                                       27CBDE483839CEAB4769C2E256084527

                                     [Not Before]
                                       7/6/2018 2:55:25 PM

                                     [Not After]
                                       7/6/2019 2:55:25 PM

                                     [Thumbprint]
                                       580F4AD5AAEFEEF5428981109ED81F5F56E6624F

PFXCertUsedForPrivateKeyExtraction :
LocationOfCertUsedDuringDecryption : C:\Users\zeroadmin\Downloads\SmallContent1.pfx
UnprotectedAESKey                  :
LocationOfAESKey                   :
AllFileOutputs                     : C:\Users\zeroadmin\Downloads\SmallContent1.txt.rsaencrypted.decrypted
DecryptedContent                   : Small amount of text
```

### Scenario 4: Encrypt/Decrypt a Big File

IMPORTANT NOTE: If a file is big enough in size, AES Encryption/Decryption will be used. To clarify, an AES Key will be generated and used to encrypt the file. That same AES Key will (itself) be written to a file. That file will be encrypted via RSA. So, when decrypting a big file that was encrypted via AES, you will need a .pfx file (or the existing X509Certificate2 object from your 'Cert:\LocalMachine\My' store), AND the RSA-Encrypted AES Key File (or the AES Key in Plain Text).

```powershell
PS C:\Users\zeroadmin> New-EncryptedFile -SourceType File -ContentToEncrypt "C:\Users\zeroadmin\Downloads\BigContent1.txt" -CNOfNewCert "BigContent1"


FileEncryptedViaRSA                :
FileEncryptedViaAES                : C:\Users\zeroadmin\Downloads\BigContent1.txt.aesencrypted
OriginalFile                       : C:\Users\zeroadmin\Downloads\BigContent1.txt.original
CertficateUsedForRSAEncryption     : [Subject]
                                       CN=BigContent1

                                     [Issuer]
                                       CN=BigContent1

                                     [Serial Number]
                                       151312EDEB8EF38644991E6C5226EC38

                                     [Not Before]
                                       7/6/2018 2:31:15 PM

                                     [Not After]
                                       7/6/2019 2:31:15 PM

                                     [Thumbprint]
                                       C036B0018AD65453D466B0BF73747C517E8A25C0

LocationOfCertUsedForRSAEncryption : Cert:\LocalMachine\My\C036B0018AD65453D466B0BF73747C517E8A25C0
UnprotectedAESKey                  : tTO7lqafrNUUuJ6ctu/PCz2SYQNaWYAZ1hWUOxzCcxY=
RSAEncryptedAESKey                 : wImpmf8ghXUtcTthHU5WO68GamIbYbamL9/JHObh4sWwpWKhC8uN9mewmHci76eFWtT25ERq3F7zDRtj7J+cYjOCoCWKqTbfg5fENr2nDmKKug0570p1xrIxUZ
                                     MgmdSyed8YXkYOnnzDaCNqXno7CabrZTY6ipKX6PLZ6Ovsb1j+yNyvXEL1Q+ly08Kfdtf2jNTx3hQ2lIbT/OwdMUls5X960UWkNyeDp1DsUk2X5DYtu7WPbhdh
                                     ci3lmnvQg8lniXP8PddzwA1PyXdfIWqDj5DT6+0RdcUW0aod7hu8Npn7UQk4UsTuNjc6bnr2KM7rQD+Hl4khxRayLPU2wcih2g==
RSAEncryptedAESKeyLocation         : C:\Users\zeroadmin\Downloads\BigContent1.aeskey.rsaencrypted
AllFileOutputs                     : {C:\Users\zeroadmin\Downloads\BigContent1.txt.aesencrypted, C:\Users\zeroadmin\Downloads\BigContent1.txt.original,
                                     C:\Users\zeroadmin\Downloads\BigContent1.aeskey.rsaencrypted, C:\Users\zeroadmin\Downloads\BigContent1.pfx}


PS C:\Users\zeroadmin> Get-DecryptedContent -SourceType File -ContentToDecrypt "$HOME\Downloads\BigContent1.txt.aesencrypted" -PathToPfxFile "$HOME\Downloads\BigContent1.pfx" -AESKeyLocation "$HOME\Downloads\BigContent1.aeskey.rsaencrypted"
Doing AES Decryption


DecryptedFiles                     : C:\Users\zeroadmin\Downloads\BigContent1.txt.aesencrypted.decrypted
FailedToDecryptFiles               : {}
CertUsedDuringDecryption           : [Subject]
                                       CN=BigContent1

                                     [Issuer]
                                       CN=BigContent1

                                     [Serial Number]
                                       151312EDEB8EF38644991E6C5226EC38

                                     [Not Before]
                                       7/6/2018 2:31:15 PM

                                     [Not After]
                                       7/6/2019 2:31:15 PM

                                     [Thumbprint]
                                       C036B0018AD65453D466B0BF73747C517E8A25C0

PFXCertUsedForPrivateKeyExtraction :
LocationOfCertUsedDuringDecryption : C:\Users\zeroadmin\Downloads\BigContent1.pfx
UnprotectedAESKey                  : tTO7lqafrNUUuJ6ctu/PCz2SYQNaWYAZ1hWUOxzCcxY=
LocationOfAESKey                   : C:\Users\zeroadmin\Downloads\BigContent1.aeskey.rsaencrypted
AllFileOutputs                     : C:\Users\zeroadmin\Downloads\BigContent1.txt.aesencrypted.decrypted
DecryptedContent                   : {Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna
                                     aliqua. Est placerat in egestas erat imperdiet sed. Cras fermentum odio eu feugiat. Egestas maecenas pharetra convallis
                                     posuere morbi. Et tortor consequat id porta. Adipiscing elit pellentesque habitant morbi tristique senectus et netus.
                                     Egestas fringilla phasellus faucibus scelerisque eleifend. Est ullamcorper eget nulla facilisi etiam dignissim diam quis
                                     enim. Lacinia at quis risus sed vulputate odio. Consequat mauris nunc congue nisi vitae suscipit tellus mauris a.
                                     Volutpat consequat mauris nunc congue nisi vitae. Arcu ac tortor dignissim convallis aenean et tortor at risus. A diam
                                     sollicitudin tempor id eu nisl nunc mi ipsum. Mus mauris vitae ultricies leo integer malesuada nunc vel. Auctor elit sed
                                     vulputate mi sit amet mauris commodo. In nibh mauris cursus mattis molestie a. Diam phasellus vestibulum lorem sed risus
                                     ultricies., , Volutpat maecenas volutpat blandit aliquam etiam erat velit scelerisque in. Eu consequat ac felis donec et
                                     odio pellentesque diam volutpat. Vitae semper quis lectus nulla at. Id aliquet risus feugiat in ante metus. Nibh tortor
                                     id aliquet lectus proin nibh nisl condimentum. Posuere ac ut consequat semper viverra nam libero. Integer malesuada nunc
                                     vel risus commodo viverra maecenas accumsan. Suspendisse in est ante in nibh mauris cursus mattis. Nulla pharetra diam
                                     sit amet nisl suscipit. Ultricies integer quis auctor elit sed vulputate mi. Ut sem nulla pharetra diam sit amet nisl
                                     suscipit adipiscing. Eget felis eget nunc lobortis mattis aliquam faucibus. Nibh mauris cursus mattis molestie. Felis
                                     eget velit aliquet sagittis id consectetur purus ut. Pellentesque habitant morbi tristique senectus., ...}
```

## Notes

* PSGallery: https://www.powershellgallery.com/packages/EncryptDecrypt
