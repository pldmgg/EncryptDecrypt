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