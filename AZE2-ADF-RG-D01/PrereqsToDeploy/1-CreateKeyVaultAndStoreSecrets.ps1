break
#
# CreateKeyVaultAndStoreSecrets.ps1
#

$rgName = 'AZEU2-ADF-rgGLOBAL'
$kVaultName = 'AZEU2-ADF-kvGLOBAL'
$location = 'EastUS2'

$AdminUserName = 'localadmin'

New-AzureRmResourceGroup -Name $rgName -Location $Location
Get-AzureRmResourceGroup -Name $rgName -Location $Location 

New-AzureRmKeyVault -ResourceGroupName $rgName -VaultName $kVaultName -Location $location -Sku Standard -EnabledForTemplateDeployment -EnabledForDeployment

#Get-AzureRmKeyVault -VaultName $kVaultName -ResourceGroupName $rgName | Remove-AzureRmKeyVault

# ------- Above this line is required, below this line is optional

# You can also create Secrets/Credentials via the Visual Studio GUI at deployment time.
## You just need the KeyVault pre-created.

$Secret = Read-Host -AsSecureString -Prompt "Enter the Password for $AdminUserName"
Set-AzureKeyVaultSecret -VaultName $kVaultName -Name $AdminUserName -SecretValue $Secret -ContentType txt

#Set-AzureKeyVaultSecret -VaultName "contoso" -Name "ITSecret" -SecretValue $Secret -Expires $Expires -NotBefore $NBF -ContentType $ContentType -Enable $True -Tags $Tags -PassThru

$contosokey = Get-AzureKeyVaultSecret -VaultName $kVaultName -Name $AdminUserName
$contosokey.Id
$contosokey.SecretValue      # SecureString
$contosokey.SecretValueText  # Text
$contosokey | gm
$contosokey | select *

# most recent key
# E.g. https://kvcontoso.vault.azure.net:443/secrets/ericlang

# specific version of key
# E.g. https://kvcontoso.vault.azure.net:443/secrets/ericlang/afa351084bba48449cc5deb984c7c4a1

# Add service account passwords to Keyvault
# Sample only

<# e.g. for CSV servicepassords.txt
User,Password
svcSQL,AGreatHoliday124
svcApp01,OnmyWay%Home
#>

Import-csv -Path servicepassords.txt | ForEach-Object {

    $Secret = ConvertTo-SecureString -String $_.Password -AsPlainText -Force
    Set-AzureKeyVaultSecret -VaultName $kVaultName -Name $_.User -SecretValue $Secret -ContentType txt

}
