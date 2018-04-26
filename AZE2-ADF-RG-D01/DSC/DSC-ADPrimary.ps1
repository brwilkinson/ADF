Configuration ADPrimary
{
    Param ( 
        [String]$DomainName = 'Contoso.com',
        [PSCredential]$AdminCreds,
        [Int]$RetryCount = 30,
        [Int]$RetryIntervalSec = 120,
        [String]$ThumbPrint,
        [String]$StorageAccountId ='/subscriptions/b8f402aa-20f7-4888-b45c-3cf086dad9c3/resourceGroups/rgGlobal/providers/Microsoft.Storage/storageAccounts/saeastus2',
        [String]$Deployment,
        [String]$NetworkID,
        [String]$AppInfo
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory 
    Import-DscResource -ModuleName xStorage
    Import-DscResource -ModuleName xPendingReboot 
    Import-DscResource -ModuleName xTimeZone 
    Import-DscResource -ModuleName xDnsServer   


    [PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("$DomainName\$($AdminCreds.UserName)", $AdminCreds.Password)

    Node $AllNodes.NodeName
    {
        Write-Verbose -Message $Nodename -Verbose

        LocalConfigurationManager
        {
            ActionAfterReboot    = 'ContinueConfiguration'
            ConfigurationMode    = 'ApplyAndMonitor'
            RebootNodeIfNeeded   = $true
            AllowModuleOverWrite = $true
        }

        xTimeZone EasternStandardTime
        { 
            IsSingleInstance = 'Yes'
            TimeZone         = "Eastern Standard Time" 
        }

        WindowsFeature InstallADDS
        {            
            Ensure = "Present"
            Name   = "AD-Domain-Services"
        }

        #-------------------------------------------------------------------
        foreach ($Feature in $Node.WindowsFeaturePresent)
        {
            WindowsFeature $Feature
            {
                Name                 = $Feature
                Ensure               = 'Present'
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
            DiskID      = "2"
            DriveLetter = 'F' 
        }

        xADDomain DC1
        {
            DomainName                    = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath                  = 'F:\NTDS'
            LogPath                       = 'F:\NTDS'
            SysvolPath                    = 'F:\SYSVOL'
            DependsOn                     = "[WindowsFeature]InstallADDS", "[xDisk]FDrive"
        }

        xWaitForADDomain DC1Forest
        {
            DomainName           = $DomainName
            DomainUserCredential = $DomainCreds
            RetryCount           = $RetryCount
            RetryIntervalSec     = $RetryIntervalSec
            DependsOn            = "[xADDomain]DC1"
        } 

        xADRecycleBin RecycleBin
        {
            EnterpriseAdministratorCredential = $DomainCreds
            ForestFQDN                        = $DomainName
            DependsOn                         = '[xWaitForADDomain]DC1Forest'
        }


        # when the DC is promoted the DNS (static server IP's) are automatically set to localhost (127.0.0.1 and ::1) by DNS
        # I have to remove those static entries and just use the Azure Settings for DNS from DHCP
        Script ResetDNS
        {
            DependsOn  = '[xADRecycleBin]RecycleBin'
            GetScript  = {@{Name = 'DNSServers'; Address = {Get-DnsClientServerAddress -InterfaceAlias Ethernet* | foreach ServerAddresses}}}
            SetScript  = {Set-DnsClientServerAddress -InterfaceAlias Ethernet* -ResetServerAddresses -Verbose}
            TestScript = {Get-DnsClientServerAddress -InterfaceAlias Ethernet* -AddressFamily IPV4 | 
                    Foreach {! ($_.ServerAddresses -contains '127.0.0.1')}}
        }
	
        # ADuser -------------------------------------------------------------------
        foreach ($User in $Node.ADUserPresent)
        {
            xADUser $User.UserName
            {
                DomainName                    = $DomainName
                UserName                      = $User.Username
                Description                   = $User.Description
                Enabled                       = $True
                Password                      = $DomainCreds
                DomainAdministratorCredential = $DomainCreds
            }
            $dependsonUser += @("[xADUser]$($User.Username)")
        }

        # ADGroup -------------------------------------------------------------------
        foreach ($Group in $Node.ADGroupPresent)
        {
            xADGroup $Group.GroupName
            {
                Description      = $Group.Description
                GroupName        = $Group.GroupName
                GroupScope       = 'DomainLocal'
                MembersToInclude = $Group.MembersToInclude 			 
            }
            $dependsonADGroup += @("[xADGroup]$($Group.GroupName)")
        }

        # Add DNS Record------------------------------------------------------------
        Foreach ($DNSRecord in $Node.AddDnsRecordPresent)    
        {
            # Prepend Arecord Target with networkID (10.144.143)
            if ($DnsRecord.RecordType -eq "ARecord")
            {
                $Target = $DnsRecord.DNSTargetIP -f $networkID 
            }
		
            xDnsRecord $DNSRecord.DnsRecordName
            {
                Ensure = "present"
                Name   = $DNSRecord.DnsRecordName
                Target = $Target
                Type   = $DNSRecord.RecordType
                Zone   = $DomainName
            }
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
                $t = New-JobTrigger -Once -At (Get-Date).AddMinutes(5)
                $o = New-ScheduledJobOption -RunElevated
				Get-ScheduledJob -Name DNSUpdate -ErrorAction SilentlyContinue | Unregister-ScheduledJob
                Register-ScheduledJob -ScriptBlock {Restart-Computer -Force} -Trigger $t -Name DNSUpdate -ScheduledJobOption $o
			}
            TestScript = {Get-DnsClientServerAddress -InterfaceAlias Ethernet* -AddressFamily IPV4 | 
                    Foreach {! ($_.ServerAddresses -contains '8.8.8.8')}
            }
        }

    }
}#Main



#break
#$cred = Get-Credential localadmin
#ADPrimary -AdminCreds $cred -Environment D -DeploymentID 3 -ConfigurationData *-configurationdata.psd1

#Start-DscConfiguration -path .\ADPrimary -wait -verbose -Force