break
#
# PreReqDSCModuleListAutomation.ps1
#
# 

############################################
# Get Module URL's from PowerShell Gallery
############################################

$Modules = @('xPSDesiredStateConfiguration','xActiveDirectory','xStorage','xPendingReboot',
'xComputerManagement','xWebAdministration','xSQLServer','xFailoverCluster','xnetworking',
'SecurityPolicyDSC','xTimeZone','xSystemSecurity','xRemoteDesktopSessionHost',
 'xRemoteDesktopAdmin','xDSCFirewall','xWindowsUpdate','PackageManagementProviderResource','xDnsServer','xSmbShare',
 'AzureRm.Profile','AzureRm.Compute','AzureRm.Compute','AzureRM.KeyVault','AzureRM.Compute','AzureRM.Resources',
 'AzureRM.Storage','AzureRM.Backup','AzureRM.OperationalInsights','AzureRM.Automation')

# Option 1) Create the JSON file format for the modules to be loaded to AA from templates
# These are referenced in: 1-azuredeploy-LogAnalytics.json

$modules | ForEach-Object {
    $modulename = $_
    $module = Find-Module -Name $modulename 
    $Link = $module.RepositorySourceLocation + 'package/' + $module.Name + '/' + $module.Version

@"
 {"name": "$($module.Name)",`t"url": "$Link"},
"@

} 

<# Example Output
 {"name": "xPSDesiredStateConfiguration",   "url": "https://www.powershellgallery.com/api/v2/package/xPSDesiredStateConfiguration/7.0.0.0"},
 {"name": "xActiveDirectory",               "url": "https://www.powershellgallery.com/api/v2/package/xActiveDirectory/2.16.0.0"},
 {"name": "xStorage",                       "url": "https://www.powershellgallery.com/api/v2/package/xStorage/3.2.0.0"},
 {"name": "xPendingReboot",                 "url": "https://www.powershellgallery.com/api/v2/package/xPendingReboot/0.3.0.0"},
 {"name": "xComputerManagement",            "url": "https://www.powershellgallery.com/api/v2/package/xComputerManagement/3.0.0.0"},
#>

# Option 2) Directly upload them to Azure Automation from Gallery

$modules | ForEach-Object {
    $modulename = $_
    $module = Find-Module -Name $modulename
    $Link = $module.RepositorySourceLocation + 'package/' + $module.Name + '/' + $module.Version
    New-AzureRmAutomationModule @common -Name $modulename -ContentLink $Link
}