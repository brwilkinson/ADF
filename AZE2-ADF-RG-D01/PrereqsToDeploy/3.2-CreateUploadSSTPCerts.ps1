break
#
# CreateUploadSSTPCerts.ps1
#
#
# When using a Point to Site VPN for access into Azure, you need some Client Certs to connect

# Create root cert for Point to Site (SSTP)
$p2scert = New-SelfSignedCertificate -Type Custom -KeySpec Signature -Subject "CN=p2sMyAppRootCert" -KeyExportPolicy Exportable -HashAlgorithm sha256 `
-KeyLength 2048 -CertStoreLocation Cert:\LocalMachine\My -KeyUsage CertSign -KeyUsageProperty Sign
$p2scert

#Thumbprint                                Subject                                                                                                                        
#----------                                -------                                                                                                                        
#3172CA54CD10B5E98ADE654A46FD3558BF67176D  CN=p2sMyAppRootCert 

# Export the certs
$certPath = "c:\certs"
$certPwd = read-host -AsSecureString
Export-PfxCertificate -Password $PW -FilePath $CertPath\p2sMyAppRootCert.pfx -Cert $p2scert
Export-Certificate -FilePath $CertPath\p2sMyAppRootPublic.cer -Cert $p2scert 
$fileContentBytes = Get-Content -Path $CertPath\p2sMyAppRootPublic.cer -Encoding Byte
$SS = [System.Convert]::ToBase64String($fileContentBytes) | ConvertTo-SecureString -AsPlainText -Force

<#
#### create client certs from existing root cert, import the Root Cert first, password required ####
$certPath = "c:\certs"
$certPwd = read-host -AsSecureString 
$p2scert = Import-PfxCertificate -FilePath $certPath\p2sMyAppRootCert.pfx -CertStoreLocation Cert:\LocalMachine\My -Password $certPwd
#>

# Note $p2scert comes from above when creating the cert

# Create certs for a list of people
foreach ($userId in @("eXXXXXX1", "eXXXXXX2", "eXXXXXX3", "eXXXXXX4", "eXXXXXX5"))
{
    $cert = New-SelfSignedCertificate -Type Custom -KeySpec Signature -Subject "CN=$userId" -KeyExportPolicy Exportable -HashAlgorithm sha256 `
        -KeyLength 2048 -CertStoreLocation Cert:\LocalMachine\My -Signer $p2scert -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")

    $pw = ConvertTo-SecureString -force -AsPlainText -string ("$userId" + "az")

    # Set a default password that is known to the user, use must have cert and password to install.
    $a = Export-PfxCertificate -Password $PW -FilePath $CertPath\$userId.pfx -Cert $cert -ChainOption BuildChain
    
    # record the userID and Thumbprint information, so that you can revoke individual certs  in the portal on the P2S VPN
    echo "$($cert.Thumbprint) $userId"
}
########################################################

# Create cert for an individual
$cert = New-SelfSignedCertificate -Type Custom -KeySpec Signature -Subject "CN=eXXXXXX8" -KeyExportPolicy Exportable -HashAlgorithm sha256 `
          -KeyLength 2048 -CertStoreLocation Cert:\LocalMachine\My -Signer $p2scert -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")

