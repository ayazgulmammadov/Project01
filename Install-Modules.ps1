$Modules = @('xCertificate', 'xPSDesiredStateConfiguration', 'xWebAdministration')
foreach ($Module in $Modules) {
    if (!(Get-Module $Module)) {
        Install-Module -Verbose $Module -Force
    }
}