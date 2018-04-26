#Requires -Version 3
#Requires -Module AzureRM.Resources
#Requires -Module Azure.Storage
#Requires -Module AzureRm.Profile


<# 
.Synopsis 
   Deploy ARM Templates in a custom way, to streamline deployments 
.DESCRIPTION 
   This is a customization of the deployment scripts available on the Quickstart or within Visual Studio Resource group Deployment Solution.
   Some of the efficiencies built into this are:
   1) Templates from the same project always upload to the same Storage Account Container
   2) Only files that have been modified are re-uploaded to the Storage Container.
        2.1) This uses git -C $ArtifactStagingDirectory diff --name-only to determine which files have been modified
   3) Only DSC files/Module are repackaged and uploaded if the DSC ps1 files are modified
   4) You can still upload all of the files by using the -FullUpload Switch
   5) You can skip all uploads by using the -NoUpload Switch
   6) You will have to set the $ArtifactStagingDirectory to the working directory where you save your project.
        6.1) You could also just set that to the $pwd, then set your location to the directory with your templates before deploying
   7) You set the Default orchestration template to deploy with $TemplateFile, however you can also pass in the Template File Path to deploy an alternate template file.
   8) You set the Default parameter file with $TemplateParametersFile
   9) You should modify the Parameters to match your naming standard for your Resource Groups
        9.1) I use AZE2-ADF-RG-D1,AZE2-ADF-RG-T2,AZE2-ADF-RG-P3 for Dev, Test, Prod RG's
   10) If you currently deploy from Visual Studio I would recommend to try this Script in VS Code
        10.1) It's super fast to deploy by commandline, without having to use the mouse
        10.2) Not having to upload the artifacts each time saves to much time, your Dev cycles will be enhanced.
        10.3) Create a workspace in VS Code with all of your Repo Directories, than access all your code from the single place
   11) Let me know if you have any ideas or feedback

.EXAMPLE 
    ARMDeploy -DP D1

    WARNING: Using parameter file: D:\Repos\AZE2-ADF-RG-D01\AZE2-ADF-RG-D01\azuredeploy.1-dev.parameters.json
    WARNING: Using template file:  D:\Repos\AZE2-ADF-RG-D01\AZE2-ADF-RG-D01\0-azuredeploy-ALL.json

    VERBOSE: _artifactsLocation
    WARNING: https://stageeus2.blob.core.windows.net/aze2-adf-rg-stageartifacts
    VERBOSE: Environment
    WARNING: D
    VERBOSE: DeploymentDebugLogLevel
    WARNING: None
    VERBOSE: DeploymentID
    WARNING: 1
    VERBOSE: _artifactsLocationSasToken
    WARNING: System.Security.SecureString
    VERBOSE: TemplateFile
    WARNING: D:\Repos\AZE2-ADF-RG-D01\AZE2-ADF-RG-D01\0-azuredeploy-ALL.json
    VERBOSE: TemplateParameterFile
    WARNING: D:\Repos\AZE2-ADF-RG-D01\AZE2-ADF-RG-D01\azuredeploy.1-dev.parameters.json
        
    Name                     Length LastModified
    ----                     ------ ------------
    5-azuredeploy-VMApp.json  32669 4/19/2018 5:06:23 AM +00:00

    VERBOSE: Performing the operation "Creating Deployment" on target "AZE2-ADF-RG-D1".
    VERBOSE: 11:12:52 PM - Template is valid.
    VERBOSE: 11:12:54 PM - Create template deployment '0-azuredeploy-ALL-2018-04-18-2312'
    VERBOSE: 11:12:54 PM - Checking deployment status in 5 seconds
    VERBOSE: 11:13:00 PM - Checking deployment status in 5 seconds 
.EXAMPLE
    ARMDeploy -DP D2 -TF .\5-azuredeploy-VMApp.json -DeploymentName AppServers
#> 

Function Start-AzureRMDeploy
{
    Param(
        [alias('Dir', 'Path')]
        #[string] $ArtifactStagingDirectory = $pwd.path,
        [string] $ArtifactStagingDirectory = 'D:\Repos\AZE2-ADF-RG-D01\AZE2-ADF-RG-D01',
        [string] $DSCSourceFolder = $ArtifactStagingDirectory + '.\DSC',

        [alias('TF')]
        [string] $TemplateFile = "$ArtifactStagingDirectory\0-azuredeploy-ALL.json",
        [string] $TemplateParametersFile = "$ArtifactStagingDirectory\azuredeploy.1-dev.parameters.json",

        [parameter(mandatory)]
        [alias('DP')]
        [validateset('D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8', 'D9', 'P0', 'P1')]
        [string]$Deployment,
    
        [string] $DeploymentName = ((Get-ChildItem $TemplateFile).BaseName + '-' + ((Get-Date)).ToString('yyyy-MM-dd-HHmm')),

        # [validateset('AZE2-ADF-RG-D01','AZE2-ADF-RG-D02','AZE2-ADF-RG-D03','AZE2-ADF-RG-D04','AZE2-ADF-RG-D05',
        #             'AZE2-ADF-RG-D06','AZE2-ADF-RG-D07','AZE2-ADF-RG-D08','AZE2-ADF-RG-D09')]
        # [alias('RG','RGName')]
        # [string] $ResourceGroupName,

        [alias('No', 'NoUpload')]
        [switch] $DoNotUpload,
        [switch] $FullUpload,
        [string] $StorageAccountName = 'stageeus2',
        [string] $ResourceGroupLocation = 'eastus2',
        [switch] $ValidateOnly,
        [string] $DebugOptions = "None"
    )

    try
    {
        [Microsoft.Azure.Common.Authentication.AzureSession]::ClientFactory.AddUserAgent("BRW-Azure-Deployment-Framework-$UI$($host.name)".replace(" ", "_"), "1.0")
    }
    catch
    {
        Write-Warning -message $_ 
    }

    $ErrorActionPreference = 'Stop'
    Set-StrictMode -Version 3

    function Format-ValidationOutput
    {
        param ($ValidationOutput, [int] $Depth = 0)
        Set-StrictMode -Off
        return @($ValidationOutput | Where-Object { $_ -ne $null } | ForEach-Object { @('  ' * $Depth + ': ' + $_.Message) + @(Format-ValidationOutput @($_.Details) ($Depth + 1)) })
    }

    $ResourceGroupName = ('AZE2-ADF-RG-' + $Deployment)
    
    # Use the same storage container for the same set of deployment templates.
    #[string] $StorageContainerName = $ResourceGroupName.ToLowerInvariant() + '-stageartifacts'
    [string] $StorageContainerName = 'AZE2-ADF-RG-stageartifacts'.ToLowerInvariant()

    $OptionalParameters = @{}
    $TemplateArgs = @{}

    if ( -not $OptionalParameters['Environment'] ) 
    {
        $OptionalParameters['Environment'] = $Deployment.substring(0, 1)
    }

    if ( -not $OptionalParameters['DeploymentID'] ) 
    {
        $OptionalParameters['DeploymentID'] = $Deployment.substring(1, 1)
    }

    $StorageAccount = Get-AzureRmStorageAccount | Where-Object {$_.StorageAccountName -eq $StorageAccountName}

    # Generate the value for artifacts location if it is not provided in the parameter file
    if ( -not $OptionalParameters['_artifactsLocation'] ) 
    {
        $OptionalParameters['_artifactsLocation'] = $StorageAccount.Context.BlobEndPoint + $StorageContainerName
    }

    # Generate a 4 hour SAS token for the artifacts location if one was not provided in the parameters file
    if ( -not $OptionalParameters['_artifactsLocationSasToken'] )
    {
        $OptionalParameters['_artifactsLocationSasToken'] = New-AzureStorageContainerSASToken -Container $StorageContainerName -Context $StorageAccount.Context -Permission r -ExpiryTime (Get-Date).AddHours(4)
    }

    Write-warning -Message "Using parameter file: $TemplateParametersFile"
    Write-warning -Message "Using template file:  $TemplateFile"

    if ( -not $ValidateOnly ) 
    {
        $OptionalParameters.Add('DeploymentDebugLogLevel', $DebugOptions)
    }

    if ( -not $DoNotUpload ) 
    {
        # Convert relative paths to absolute paths if needed
        $ArtifactStagingDirectory = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $ArtifactStagingDirectory))
        $DSCSourceFolder = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($PSScriptRoot, $DSCSourceFolder))

        # Parse the parameter file and update the values of artifacts location and artifacts location SAS token if they are present
        $JsonParameters = Get-Content $TemplateParametersFile -Raw | ConvertFrom-Json
        if ( -not ($JsonParameters | Get-Member -Type NoteProperty 'parameters') ) 
        {
            $JsonParameters = $JsonParameters.parameters
        }

        # Create the storage account if it doesn't already exist
        if ( -not $StorageAccount ) 
        {
            $StorageResourceGroupName = 'ARM_Deploy_Staging'
            New-AzureRmResourceGroup -Location $ResourceGroupLocation -Name $StorageResourceGroupName -Force
            $StorageAccount = New-AzureRmStorageAccount -StorageAccountName $StorageAccountName -Type 'Standard_LRS' -ResourceGroupName $StorageResourceGroupName -Location $ResourceGroupLocation
        }

        # Copy files from the local storage staging location to the storage account container
        New-AzureStorageContainer -Name $StorageContainerName -Context $StorageAccount.Context -ErrorAction SilentlyContinue *>&1

        if ( -not $FullUpload )
        {
            # Create DSC configuration archive only for the files that changed
            git -C $ArtifactStagingDirectory diff --name-only | where {$_ -match 'ps1$'} | Foreach-Object {
                $File = Get-Item -path (join-path -childpath $_ -path (Split-Path -Path $ArtifactStagingDirectory))
                $DSCArchiveFilePath = $File.FullName.Substring(0, $File.FullName.Length - 4) + '.zip'
                Publish-AzureRmVMDscConfiguration $File.FullName -OutputArchivePath $DSCArchiveFilePath -Force -Verbose
            }

            git -C $ArtifactStagingDirectory diff --name-only | ForEach-Object {
                $File = Get-Item -path (join-path -childpath $_ -path (Split-Path -Path $ArtifactStagingDirectory))
                Set-AzureStorageBlobContent -File $File.FullName -Blob $File.FullName.Substring($ArtifactStagingDirectory.length + 1) -Container $StorageContainerName -Context $StorageAccount.Context -Force |
                    Select Name, Length, LastModified
            }

            sleep -Seconds 4
        }
        else # only re-zip DSC files and upload on FullUpload
        {
            # Create DSC configuration archive for all files
            if (Test-Path $DSCSourceFolder) 
            {
                Get-ChildItem $DSCSourceFolder -File -Filter '*.ps1' | ForEach-Object {

                    $DSCArchiveFilePath = $_.FullName.Substring(0, $_.FullName.Length - 4) + '.zip'
                    Publish-AzureRmVMDscConfiguration $_.FullName -OutputArchivePath $DSCArchiveFilePath -Force -Verbose
                }
            }

            Get-ChildItem -Path $ArtifactStagingDirectory -Recurse -File -Include *.json, *.zip, *.psd1 | ForEach-Object {
                Set-AzureStorageBlobContent -File $_.FullName -Blob $_.FullName.Substring($ArtifactStagingDirectory.length + 1) -Container $StorageContainerName -Context $StorageAccount.Context -Force 
            } | Select Name, Length, LastModified
        }

    }

    $OptionalParameters['_artifactsLocationSasToken'] = ConvertTo-SecureString $OptionalParameters['_artifactsLocationSasToken'] -AsPlainText -Force

    $TemplateArgs.Add('TemplateFile', $TemplateFile)
    $TemplateArgs.Add('TemplateParameterFile', $TemplateParametersFile)

    # Create the resource group only when it doesn't already exist
    if ( -not (Get-AzureRmresourcegroup -Name $ResourceGroupName -Location $ResourceGroupLocation -Verbose -ErrorAction SilentlyContinue)) 
    {
        New-AzureRmResourceGroup -Name $ResourceGroupName -Location $ResourceGroupLocation -Verbose -Force -ErrorAction Stop
    }

    if ($ValidateOnly)
    {
        $ErrorMessages = Format-ValidationOutput (Test-AzureRmResourceGroupDeployment -ResourceGroupName $ResourceGroupName @TemplateArgs @OptionalParameters)
        if ($ErrorMessages)
        {
            Write-Output '', 'Validation returned the following errors:', @($ErrorMessages), '', 'Template is invalid.'
        }
        else
        {
            Write-Output '', 'Template is valid.'
        }
    }
    else
    {
        $OptionalParameters.getenumerator() | foreach {
            write-verbose $_.Key -verbose
            Write-Warning $_.Value
        }

        $TemplateArgs.getenumerator() | foreach {
            write-verbose $_.Key -verbose
            Write-Warning $_.Value
        }
    
        New-AzureRmResourceGroupDeployment -Name $DeploymentName `
            -ResourceGroupName $ResourceGroupName @TemplateArgs `
            @OptionalParameters -Force -Verbose -ErrorVariable ErrorMessages
        if ($ErrorMessages)
        {
            Write-Output '', 'Template deployment returned the following errors:', @(@($ErrorMessages) | 
                    ForEach-Object { $_.Exception.Message.TrimEnd("`r`n") })
        }
    }

}#Start-AzureRMDeploy

New-Alias -Name ARMDeploy -Value Start-AzureRMDeploy -Force