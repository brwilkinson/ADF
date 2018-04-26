# break
#
# PreReqDSCModuleList.ps1
#
# This script will remove old modules and download the newest versions

$Modules = @('xPSDesiredStateConfiguration','xActiveDirectory','xStorage','xPendingReboot',
	'xComputerManagement','xWebAdministration','SQLServerDsc','xFailoverCluster','xnetworking',
	'SecurityPolicyDSC','xTimeZone','xSystemSecurity','xRemoteDesktopSessionHost','NTFSSecurity',
	'xRemoteDesktopAdmin','xDSCFirewall','xWindowsUpdate','PackageManagementProviderResource','xDnsServer','xSmbShare')

# remove old version of the Modules/Resources
Get-Module -ListAvailable -Name  $Modules | foreach {
    $_.ModuleBase | Remove-Item -Recurse -Force
}

# Bootstrap the nuget agent
Find-Package -ForceBootstrap -Name xComputerManagement

# Install required SQL Module, this specific version is required
Install-Module -Name SQLServer -RequiredVersion '21.0.17199'

# Install new versions of the modules
Install-Package -name $Modules -Force -AllowClobber

Get-Module -Name $Modules -ListAvailable

