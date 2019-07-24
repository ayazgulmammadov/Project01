param (
    [string] $certPath
)

#generate password
$secret = [System.Web.Security.Membership]::GeneratePassword(50, 1) 
$pattern = '[^a-zA-Z0-9#$!]' 
$secret = ($secret -replace $pattern, '').Substring(1, 16)
$certPsw = ConvertTo-SecureString -String $secret -AsPlainText -Force

#create certificate
$cert = New-SelfSignedCertificate `
    -Type DocumentEncryptionCert `
    -DnsName 'DscEncryptionCert' `
    -HashAlgorithm SHA256

#export pfx certificate
$cert | Export-PfxCertificate `
    -FilePath $certPath `
    -Password $certPsw `
    -Force
