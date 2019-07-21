Configuration Main
{

    Param ( 
        [string] $nodeName,
        [string] $certUri,
        [string] $certPass
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xCertificate
    Import-DscResource -ModuleName xPSDesiredStateConfiguration
    Import-DscResource -ModuleName xWebAdministration


    Node $nodeName
    {
        if ($nodeName -match "prod"){
            WindowsFeature WebCompression {
                Ensure = "Present"
                Name = "Web-Dyn-Compression"
                DependsOn = "[WindowsFeature]InstallWebServer"
            }
            xWebAppPoolDefaults PoolDefaults
            {
                ApplyTo                 = 'Machine'
                ManagedRuntimeVersion   = 'v4.0'
                IdentityType            = 'LocalSystem'
                DependsOn = "[xWebAppPool]BloggeAppPool"
            }
        }
        WindowsFeature InstallWebServer {
            Ensure = "Present"
            Name   = "Web-Server"
        }
        WindowsFeature InstallWebMgmtTools {
            Ensure    = "Present"
            Name      = "Web-Mgmt-Tools"
            DependsOn = "[WindowsFeature]InstallWebServer"
        }
        WindowsFeature InstallWebMgmtService {
            Ensure    = "Present"
            Name      = "Web-Mgmt-Service"
            DependsOn = "[WindowsFeature]InstallWebServer"
        }
        WindowsFeature InstallASP {
            Ensure    = "Present"
            Name      = "Web-Asp-Net45"
            DependsOn = "[WindowsFeature]InstallWebServer"
        }
        WindowsFeature WindowsAuthentication {
            Name   = "Web-Windows-Auth"
            Ensure = "Present"
            DependsOn = "[WindowsFeature]InstallWebServer"
        }
        xRemoteFile DownloadURLRewrite {
            Uri             = "https://download.microsoft.com/download/C/9/E/C9E8180D-4E51-40A6-A9BF-776990D8BCA9/rewrite_amd64.msi"
            DestinationPath = "C:\rewrite_amd64.msi"
        }
        xRemoteFile DownloadWebDeploy {
            Uri             = "https://download.microsoft.com/download/0/1/D/01DC28EA-638C-4A22-A57B-4CEF97755C6C/WebDeploy_amd64_en-US.msi"
            DestinationPath = "C:\WebDeploy_amd64_en-US.msi"
        }
        xRemoteFile CopyCert {
            Uri             = "$certUri"
            DestinationPath = "C:\ayaz.javid.club.pfx"
        }
        File CreateFolder {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = "C:\inetpub\wwwroot\Blogge"
            DependsOn       = "[WindowsFeature]InstallWebServer"
        }
        Package InstallURLRewrite {
            Name      = "IIS URL Rewrite Module 2"
            Ensure    = "Present"
            Path      = "C:\rewrite_amd64.msi"
            ProductId = "08F0318A-D113-4CF0-993E-50F191D397AD"
            DependsOn = @("[xRemoteFile]DownloadURLRewrite", "[WindowsFeature]InstallWebServer")
        }
        Package InstallWebDeploy {
            Name      = "Microsoft Web Deploy 3.6"
            Ensure    = "Present"
            Path      = "C:\WebDeploy_amd64_en-US.msi"
            Arguments = "ADDLOCAL=ALL"
            ProductId = "6773A61D-755B-4F74-95CC-97920E45E696"
            DependsOn = @("[xRemoteFile]DownloadWebDeploy", "[WindowsFeature]InstallWebMgmtService")
        }
        Service WebMgmtService {
            Name = "WMSVC"
            StartupType = "Automatic"
            State = "Running"
            DependsOn = @("[Registry]RemoteManagement", "[Package]InstallWebDeploy")
        }
        Service WebDeployRemoteAgent {
            Name = "MsDepSvc"
            StartupType = "Automatic"
            State = "Running"
            DependsOn = @("[Registry]RemoteManagement", "[Package]InstallWebDeploy")
        }
        Registry RemoteManagement {
            Key = 'HKLM:\SOFTWARE\Microsoft\WebManagement\Server'
            ValueName = 'EnableRemoteManagement'
            ValueType = 'Dword'
            ValueData = '1'
            DependsOn = "[WindowsFeature]InstallWebMgmtService"
       }
        xWebsite DefaultSite {
            Ensure       = "Present"
            Name         = "Default Web Site"
            State        = "Stopped"
            PhysicalPath = "C:\inetpub\wwwroot"
            DependsOn    = "[WindowsFeature]InstallWebServer" 
        }
        xWebAppPool BloggeAppPool {
            Name = "BloggeAppPool"
        }
        xWebsite WebSite {
            Ensure       = "Present"
            Name         = "Project1"
            State        = "Started"
            PhysicalPath = "C:\inetpub\wwwroot\Blogge"
            ApplicationPool = "BloggeAppPool"
            DependsOn    = @("[File]CreateFolder", "[Script]InstallCert", "[xWebAppPool]BloggeAppPool")
            BindingInfo  = @(
                MSFT_xWebBindingInformation {
                    Protocol  = "HTTP" 
                    Port      = "80"
                    IPAddress = "*"
                    HostName  = "ayaz.javid.club"
                }
                MSFT_xWebBindingInformation {
                    Protocol              = "HTTPS" 
                    Port                  = "443"
                    IPAddress             = "*"
                    HostName              = "ayaz.javid.club"
                    CertificateThumbprint = "2a1a6970207203c05247510e287c4bd820d2e8b6"
                    CertificateStoreName  = "WebHosting"
                }
            )
        }
        Script InstallCert {
            TestScript = {
                if ((Get-ChildItem Cert:\LocalMachine\WebHosting).Thumbprint -contains "‎2a1a6970207203c05247510e287c4bd820d2e8b6") { return $true }
                else { return $false }
            }
            SetScript  = {
                $psw = "$Using:certPass" | ConvertTo-SecureString -AsPlainText -Force
                $certPath = "C:\ayaz.javid.club.pfx"
                Import-PfxCertificate -FilePath $certPath -Password $psw -CertStoreLocation Cert:\LocalMachine\WebHosting -Exportable
            }
            GetScript  = {
                $certs = Get-ChildItem -Path Cert:\LocalMachine\WebHosting -Recurse
                return @{result = $certs.Thumbprint }
            }
            DependsOn  = "[xRemoteFile]CopyCert"
        }
    }
}