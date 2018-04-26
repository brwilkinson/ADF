break
#
# DeterminePublisherImageOffers.ps1
#

# 1 Find the available SKUs for Virtual Machines
    
# 1 retrieve the list of publisher names of images in Azure
$Location="EASTUS2"
Get-AzureRMVMImagePublisher -Location $location | Select PublisherName

# 2 obtain offerings from the publisher
$pubName="MicrosoftWindowsServer"
$pubname  = 'MicrosoftSQLServer'
Get-AzureRMVMImageOffer -Location $location -Publisher $pubName | Select Offer

# 3 retrieve the SKUs of the offering
$offerName="WindowsServer"
$offerName="SQL2016SP1-WS2016-BYOL"
Get-AzureRMVMImageSku -Location $location `
    -Publisher $pubName `
    -Offer $offerName | 
    Select Skus


$SKU = '2016-Datacenter'
Get-AzureRmVMImage -Location $Location -PublisherName $pubName -Offer $offerName -Skus $SKU

# Sample output:

    # Publisher : MicrosoftWindowsServer
    # Offer     : WindowsServer
    
    <#
    Skus
    ----
    2008-R2-SP1
    2012-Datacenter
    2012-R2-Datacenter
    2016-Datacenter
    #>
    
    # SQL BYOL
    # Publisher : MicrosoftSQLServer
    # Offers    : SQL2016SP1-WS2016
    # Offers    : SQL2016SP1-WS2016-BYOL
    
    <#
    Skus
    ----
    Enterprise
    Standard
    #>
    