break
#
# CreateWebAppFirewallCert.ps1
#
# The Web Application Firewall is an Application Gateway for your Application

# We need the base64 password uploaded for the Web Application Firewall, that will also use this cert
# Do this for all regions

# See CreateUploadWebCert for source of these certificates

$kVaultName = 'AZEU2-ADF-kvGLOBAL'

# Front End SSL Cert
$fileContentBytes = Get-Content -Path $CertPath\MultiDomainwildcard.pfx -Encoding Byte
$SS = [System.Convert]::ToBase64String($fileContentBytes) | ConvertTo-SecureString -AsPlainText -Force
Set-AzureKeyVaultSecret -VaultName $kVaultName -Name MultiDomainwildcardBase64 -SecretValue $SS -ContentType txt

# Authentication certs
$fileContentBytes = Get-Content -Path $CertPath\MultiDomainwildcard.cer -Encoding Byte
$SS = [System.Convert]::ToBase64String($fileContentBytes) | ConvertTo-SecureString -AsPlainText -Force
Set-AzureKeyVaultSecret -VaultName $kVaultName -Name MultiDomainwildcardBase64Public -SecretValue $SS -ContentType txt
