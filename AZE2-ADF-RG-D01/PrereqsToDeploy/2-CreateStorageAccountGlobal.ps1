break
# Create the global storage acounts
## Used for File and Blob Storage for assets/artifacts
## Used for Blob and Table Storage for the Diagnostics logs

$rgName = 'AZEU2-ADF-rgGLOBAL'
$saname = 'saadfglobaleus2'
$saNameDiag = 'sanadfglobaldiageus2'

# create storage accounts
New-AzureRmStorageAccount -ResourceGroupName $rgName -Name $saname -SkuName Standard_LRS -Location $location -Kind Storage -EnableEncryptionService "Blob,File"
New-AzureRmStorageAccount -ResourceGroupName $rgName -Name $sanameDiag -SkuName Standard_LRS -Location $location -Kind Storage -EnableEncryptionService "Blob,File"


# Add the storage account Keys to Keyvault - No longer required we can pull the key with listkeys()
# $SS = (Get-AzureRmStorageAccountKey -ResourceGroupName $rgName -Name $saname)[1].value | ConvertTo-SecureString -AsPlainText -Force
# Set-AzureKeyVaultSecret -VaultName $kVaultName -Name StorageAccountKeySource -SecretValue $SS -ContentType txt



