break
#
# ConnectToAzureSelectSubscription.ps1
#
# AZEUS2-BKFS-AFT01

# Login to Azure, watch for auth dialog pop up
Add-AzureRMAccount

# List all subscription that you have access to with that user account
Get-AzureRmSubscription 

# Select the one that you want to work in
Select-AzureRmSubscription -SubscriptionId dad159c2-ca67-40c3-878e-3408f4bd92b8

# Get the context that you are currently working in 
# Useful if you have been away from the console and return

Get-AzureRmContext

# Some other useful commands

Get-AzureRmResourceGroup

Get-AzureRmResourceGroup | select *Name

Get-AzureRmVM | select *Name

Get-AzureRmKeyVault | select *name

Get-AzureRmStorageAccount | select *name