#Requires -Version 3
#Requires -Module AzureRM.Resources
#Requires -Module Azure.Storage
#Requires -Module AzureRm.Profile

Function Start-AzureRMDeploy
{
    Param(
        [alias('Dir', 'Path')]
        #[string] $ArtifactStagingDirectory = $pwd.path,
        [string] $ArtifactStagingDirectory = 'D:\Repos\AZE2-ADF-RG-D01\AZE2-ADF-RG-D01',
        [string] $DSCSourceFolder = $ArtifactStagingDirectory + '.\DSC',

        [string] $TemplateParametersFile = "$ArtifactStagingDirectory\azuredeploy.1-dev.parameters.json",
    
        [string] $DeploymentName = ((Get-ChildItem $TemplateFile).BaseName + '-' + ((Get-Date)).ToString('yyyy-MM-dd-HHmm')),

        [validateset('AZE2-ADF-RG-D1','AZE2-ADF-RG-D2','AZE2-ADF-RG-D3','AZE2-ADF-RG-D4','AZE2-ADF-RG-D5',
                    'AZE2-ADF-RG-D6','AZE2-ADF-RG-D7','AZE2-ADF-RG-D8','AZE2-ADF-RG-D9')]
        [alias('RG','RGName')]
        [string] $ResourceGroupName,

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

    $OptionalParameters = @{}
    $TemplateArgs = @{}

    $OptionalParameters['Environment'] = $ResourceGroupName.substring(12,1)
    $OptionalParameters['DeploymentID'] = $ResourceGroupName.substring(13,1)
    
    [string] $StorageAccountName = 'stageeus2'
    $StorageAccount = Get-AzureRmStorageAccount | Where-Object {$_.StorageAccountName -eq $StorageAccountName}

    # Use the same storage container for the same set of deployment templates.
    # We'll likely version this and create a SAS per container
    [string] $StorageContainerName = 'AZE2-ADF-RG-stageartifacts'.ToLowerInvariant()
    
    $OptionalParameters['_artifactsLocation'] = $StorageAccount.Context.BlobEndPoint + $StorageContainerName

    Write-warning -Message "Using parameter file: $TemplateParametersFile"

    $TemplateFile = "0-azuredeploy-ALL.json",

    if ( -not $ValidateOnly ) 
    {
        $OptionalParameters.Add('DeploymentDebugLogLevel', $DebugOptions)
    }

    # Parse the parameter file and update the values of artifacts location and artifacts location SAS token if they are present
    $JsonParameters = Get-Content $TemplateParametersFile -Raw | ConvertFrom-Json
    if ( -not ($JsonParameters | Get-Member -Type NoteProperty 'parameters') ) 
    {
        $JsonParameters = $JsonParameters.parameters
    }

    $OptionalParameters['_artifactsLocationSasToken'] = ConvertTo-SecureString $OptionalParameters['_artifactsLocationSasToken'] -AsPlainText -Force

    $TemplateArgs.Add('TemplateUri', $TemplateUrl)
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