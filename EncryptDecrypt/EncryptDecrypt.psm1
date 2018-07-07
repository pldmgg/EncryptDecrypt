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

        Write-Warning "'MiniLab' will probably not work with PowerShell Core..."

    }
}

# Public Functions

