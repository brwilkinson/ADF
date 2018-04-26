Configuration ADSecondary
{
    Param ( 
        [String]$DomainName = 'Contoso.com',
        [PSCredential]$AdminCreds,
        [Int]$RetryCount = 30,
        [Int]$RetryIntervalSec = 120,
        [String]$ThumbPrint,
        [String]$StorageAccountId = '/subscriptions/b8f402aa-20f7-4888-b45c-3cf086dad9c3/resourceGroups/rgGlobal/providers/Microsoft.Storage/storageAccounts/saeastus2',
        [String]$Deployment,
        [String]$NetworkID,
        [String]$AppInfo,
        [String]$SiteName = 'Default-First-Site-Name'
		)

Import-DscResource -ModuleName PSDesiredStateConfiguration
Import-DscResource -ModuleName xComputerManagement
Import-DscResource -ModuleName xActiveDirectory
Import-DscResource -ModuleName xStorage
Import-DscResource -ModuleName xPendingReboot
Import-DscResource -ModuleName xTimeZone

[PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("$DomainName\$(($AdminCreds.UserName -split '\\')[-1])", $AdminCreds.Password)

Node $AllNodes.NodeName
{
    Write-Verbose -Message $Nodename -Verbose

	LocalConfigurationManager
    {
        ActionAfterReboot   = 'ContinueConfiguration'
        ConfigurationMode   = 'ApplyAndMonitor'
        RebootNodeIfNeeded  = $true
        AllowModuleOverWrite = $true
    }

	xTimeZone EasternStandardTime
    { 
        IsSingleInstance = 'Yes'
        TimeZone         = "Eastern Standard Time" 
    }

	WindowsFeatureSet AD-Domain-Services
    {            
        Ensure = 'Present'
        Name   = 'AD-Domain-Services'
		IncludeAllSubFeature = $true
    }

	foreach ($Feature in $Node.WindowsFeaturePresent)
    {
        WindowsFeature $Feature {
            Name   = $Feature
            Ensure = 'Present'
            IncludeAllSubFeature = $true
            #Source = $ConfigurationData.NonNodeData.WindowsFeatureSource
        }
        $dependsonFeatures += @("[WindowsFeature]$Feature")
    }

    #-------------------------------------------------------------------
    if ($Node.WindowsFeatureSetAbsent)
    {
        WindowsFeatureSet WindowsFeatureSetAbsent
        {
            Ensure = 'Absent'
            Name   = $Node.WindowsFeatureSetAbsent
        }
    }

	xDisk FDrive
    {
        DiskID  = "2"
        DriveLetter = 'F'
    }

    xWaitForADDomain $DomainName
    {
        DependsOn  = '[WindowsFeatureSet]AD-Domain-Services'
        DomainName = $DomainName
        RetryCount = $RetryCount
		RetryIntervalSec = $RetryIntervalSec
        DomainUserCredential = $AdminCreds
    }

	xComputer DomainJoin
	{
		Name       = $Env:COMPUTERNAME
		DependsOn  = "[xWaitForADDomain]$DomainName"
		DomainName = $DomainName
		Credential = $DomainCreds
	}

    # reboots after DJoin
	xPendingReboot RebootForDJoin
    {
        Name      = 'RebootForDJoin'
        DependsOn = '[xComputer]DomainJoin'
    }

	xADDomainController DC2
	{
		DependsOn    = '[xPendingReboot]RebootForDJoin'
		DomainName   = $DomainName
		DatabasePath = 'F:\NTDS'
        LogPath      = 'F:\NTDS'
        SysvolPath   = 'F:\SYSVOL'
        DomainAdministratorCredential = $DomainCreds
        SafemodeAdministratorPassword = $DomainCreds
		PsDscRunAsCredential = $DomainCreds
        SiteName = $SiteName
	 }

	# Reboot outside of DSC, for DNS update, so set scheduled job to run in 5 minutes
	Script ResetDNS
    {
        DependsOn = '[xADDomainController]DC2'
        GetScript = {@{Name='DNSServers';Address={Get-DnsClientServerAddress -InterfaceAlias Ethernet* | foreach ServerAddresses}}}
        SetScript = {Set-DnsClientServerAddress -InterfaceAlias Ethernet* -ResetServerAddresses -Verbose}
        TestScript = {Get-DnsClientServerAddress -InterfaceAlias Ethernet* -AddressFamily IPV4 | 
						Foreach {! ($_.ServerAddresses -contains '127.0.0.1')}}
    }

    # Need to make sure the DC reboots after it is promoted.
	xPendingReboot RebootForPromo
    {
        Name      = 'RebootForDJoin'
        DependsOn = '[Script]ResetDNS'
    }

	# Reboot outside of DSC, for DNS update, so set scheduled job to run in 5 minutes
    Script ResetDNSDHCPFlagReboot
    {
        PsDscRunAsCredential = $DomainCreds
		DependsOn  = '[xPendingReboot]RebootForPromo'
        GetScript  = {@{Name = 'DNSServers'; Address = {Get-DnsClientServerAddress -InterfaceAlias Ethernet* | foreach ServerAddresses}}}
        SetScript  = {
            $t = New-JobTrigger -Once -At (Get-Date).AddMinutes(8)
            $o = New-ScheduledJobOption -RunElevated
			Get-ScheduledJob -Name DNSUpdate -ErrorAction SilentlyContinue | Unregister-ScheduledJob
            Register-ScheduledJob -ScriptBlock {Restart-Computer -Force} -Trigger $t -Name DNSUpdate -ScheduledJobOption $o
		}
        TestScript = {
			$Count = Get-DnsClientServerAddress -InterfaceAlias Ethernet* -AddressFamily IPV4 | Foreach ServerAddresses | Measure | Foreach Count
			if ($Count -eq 1)
			{
				$False
			}
			else
			{
				$True
			}
        }
    }
}
}#ADSecondary


break

# used for troubleshooting

#$Cred = get-credential localadmin

ADSecondary -AdminCreds $cred -ConfigurationData .\ADs-ConfigurationData.psd1 

Set-DscLocalConfigurationManager -Path .\ADSecondary -Verbose

Start-DscConfiguration -Path .\ADSecondary -Wait -Verbose -Force

Get-DscLocalConfigurationManager

Start-DscConfiguration -UseExisting -Wait -Verbose -Force

Get-DscConfigurationStatus -All