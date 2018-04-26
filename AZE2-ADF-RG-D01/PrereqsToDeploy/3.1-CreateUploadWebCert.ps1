break
#
# CreateUploadWebCert.ps1
#
# Note this Wildcard certificate can be used on all Web Server in the Environment.
# The deployment automatically installs this Cert in all required stores for it to be trusted.
# This step is required to be run on Windows 10 or Server 2016


$kVaultName = 'AZEU2-ADF-kvGLOBAL'
$CertPath = 'c:\temp\Certs'
$DNSNames = '*.myapp.local','*.contoso.com'
#--------------------------------------------------------
# Create Web cert *.contoso.com
$cert = New-SelfSignedCertificate -NotAfter (Get-Date).AddYears(5) -DnsName $DNSNames -CertStoreLocation Cert:\LocalMachine\My `
				-Provider 'Microsoft Enhanced RSA and AES Cryptographic Provider' -KeyUsageProperty All
$cert

#$PW = read-host -AsSecureString
$PW = Get-AzureKeyVaultSecret -VaultName $kVaultName -Name LocalAdmin

$PW = Read-Host -AsSecureString

Export-PfxCertificate -Password $PW -FilePath $CertPath\multidomainwildcardMulti.pfx -Cert $cert
Export-Certificate -FilePath $CertPath\multidomainwildcardMulti.cer -Cert $cert 

# Confirm the Thumbprint
Get-PfxCertificate -FilePath $CertPath\multidomainwildcardMulti.pfx 

# Thumbprint                                Subject                                                                                                                                                        
# ----------                                -------                                                                                                                                                        
# E5FAA5D9992DDA3D6FD6401E9139CB9EC3C0AAB7  CN=*.myapp.local

# Run this twice or for each region that you want to deploy into
Import-AzureKeyVaultCertificate -FilePath $CertPath\multidomainwildcardMulti.pfx -Name MultiDomainwildcard -VaultName $kVaultName -Password $PW.SecretValue
#Import-AzureKeyVaultCertificate -FilePath $CertPath\MultiDomainwildcard.pfx -Name MultiDomainwildcard -VaultName $kVaultName -Password $PW

# SecretId:  https://azeu2-myorg-kvmyappglobal.vault.azure.net:443/secrets/MultiDomainwildcard/9bbaa302884f4400b91cb6d984bd06c0

$MultiDomainwildcard = Get-AzureKeyVaultSecret -VaultName $kVaultName -Name AFTDomainwildcard
$MultiDomainwildcard.Id
# OR
Get-AzureKeyVaultCertificate -VaultName $kVaultName -Name AFTDomainwildcard

# e.g. https://azeu2-myorg-kvmyappglobal.vault.azure.net:443/secrets/MultiDomainwildcard/07534e07585c4f6ba3ffd1769af55d01

# Ensure you allow the particular user access to the keys, which allows access to certs and creds
#Set-AzureKeyVaultAccessPolicy -VaultName kvcontoso -ServicePrincipalName '8b58c31d-7cab-4152-979b-096f8f88621e' -PermissionsToKeys all
