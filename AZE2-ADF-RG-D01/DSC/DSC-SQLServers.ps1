Configuration SQLServers
{
Param ( 
    [String]$DomainName = 'Contoso.com',
    [PSCredential]$AdminCreds,
    [PSCredential]$DomainJoinCreds,
    [PSCredential]$DomainSQLCreds,
    [Int]$RetryCount = 30,
    [Int]$RetryIntervalSec = 180,
    [String]$ThumbPrint,
    [String]$StorageAccountId = '/subscriptions/b8f402aa-20f7-4888-b45c-3cf086dad9c3/resourceGroups/rgGlobal/providers/Microsoft.Storage/storageAccounts/saeastus2',
    [String]$Deployment,
    [String]$NetworkID,
    [String]$AppInfo
    )

		Import-DscResource -ModuleName PSDesiredStateConfiguration
		Import-DscResource -ModuleName xPSDesiredStateConfiguration
		Import-DscResource -ModuleName xComputerManagement
		Import-DscResource -ModuleName xActiveDirectory
		Import-DscResource -ModuleName xStorage
		Import-DscResource -ModuleName xPendingReboot
		Import-DscResource -ModuleName xWebAdministration 
		Import-DscResource -ModuleName SQLServerDsc
		Import-DscResource -ModuleName xDNSServer
		Import-DscResource -ModuleName xFailoverCluster
		Import-DscResource -ModuleName xnetworking
		Import-DscResource -ModuleName xTimeZone
		Import-DscResource -ModuleName PackageManagementProviderResource
		Import-DscResource -ModuleName StoragePoolcustom
		Import-DscResource -ModuleName SecurityPolicyDSC

		$NetBios = $(($DomainName -split '\.')[0])
		$DeploymentNumber = $Deployment.Substring(8,1)
		$enviro = $Deployment.Substring(7,1)
        $environment = "$enviro$DeploymentNumber" 
        
        # -------- MSI lookup for storage account keys to download files and set Cloud Witness
        $response = Invoke-WebRequest -UseBasicParsing -Uri http://169.254.169.254/metadata/identity/oauth2/token -Method GET -Body @{resource="https://management.azure.com/"} -Headers @{Metadata="true"}
        $ArmToken = $response.Content | ConvertFrom-Json | Foreach access_token
        $Params = @{ Method = 'POST'; UseBasicParsing = $true; ContentType = "application/json"; Headers = @{ Authorization ="Bearer $ArmToken"} }

        # Cloud Witness
        $SubscriptionGuid = 'b8f402aa-20f7-4888-b45c-3cf086dad9c3'
        $RGName           = "AZE2-ADF-RG-{0}" -f $environment 
        $SaName           = ("aze2adf{0}sawitness" -f $environment ).toLower()
        $resource = "/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Storage/storageAccounts/{2}" -f $SubscriptionGuid,$RGName,$SaName
        $Params['Uri'] = "https://management.azure.com{0}/{1}/?api-version=2016-01-01" -f $resource,'listKeys'
        $sakwitness = (Invoke-WebRequest @Params).content | ConvertFrom-Json | Foreach Keys | Select -first 1 | foreach Value
        Write-Verbose "SAK Witness: $sakwitness" -Verbose

        # Global assets to download files
        $Params['Uri'] =  "https://management.azure.com{0}/{1}/?api-version=2016-01-01" -f $StorageAccountId,'listKeys'
        $storageAccountKeySource = (Invoke-WebRequest @Params).content | ConvertFrom-Json | Foreach Keys | Select -first 1 | foreach Value
        Write-Verbose "SAK Global: $storageAccountKeySource" -Verbose      

        [PSCredential]$DomainCreds = [PSCredential]::New( $NetBios + '\' + $(($AdminCreds.UserName -split '\\')[-1]), $AdminCreds.Password )

	    $credlookup = @{
                    "localadmin" = $DomainCreds
                    "DomainJoin" = $DomainCreds
                    "SQLService" = $DomainCreds
                }
    
        $AppInfo = ConvertFrom-Json $AppInfo
        $SQLAOInfo = $AppInfo.AOInfo
        $ClusterInfo = $AppInfo.ClusterInfo


Node $AllNodes.NodeName
{
    Write-Warning -Message "AllNodes"
    Write-Verbose -Message "Node is: [$($Node.NodeName)]" -Verbose
    Write-Verbose -Message "NetBios is: [$NetBios]" -Verbose
    Write-Verbose -Message "DomainName is: [$DomainName]" -Verbose

    Write-Verbose -Message "Deployment Name is: [$deployment]" -Verbose
    Write-Verbose -Message "Deployment Number is: [$DeploymentNumber]" -Verbose
    Write-Verbose -Message "Enviro is: [$enviro]" -Verbose
    Write-Verbose -Message "Environment is: [$environment]" -Verbose
  

    # Allow this to be run against local or remote machine
    if($NodeName -eq "localhost") {
        [string]$computername = $env:COMPUTERNAME
    }
    else {
        Write-Verbose $Nodename.GetType().Fullname
        [string]$computername = $Nodename
    } 
    Write-Verbose -Message $computername -Verbose


    if ($Node.WindowsFeaturesSet)
    {
        $Node.WindowsFeaturesSet | foreach {
            Write-Verbose -Message $_ -Verbose -ErrorAction SilentlyContinue
        }
    }

	LocalConfigurationManager
    {
        ActionAfterReboot    = 'ContinueConfiguration'
        ConfigurationMode    = 'ApplyAndMonitor'
        RebootNodeIfNeeded   = $true
        AllowModuleOverWrite = $true
    }

	# Currently naming the pools after the first AO instance, need to update if multiple instances
    foreach ($Pool in $Node.StoragePools)
	{
		StoragePool $Pool.DriveLetter
		{
			FriendlyName = ($SQLAOInfo[0].InstanceName + '_' + $Pool.FriendlyName)
			DriveLetter  = $Pool.DriveLetter
			LUNS         = $Pool.LUNS
			ColumnCount  = $(if ($Pool.ColumnCount) {$Pool.ColumnCount} else {0})
		}
		$dependsonStoragePoolsPresent += @("[xDisk]$($disk.DriveLetter)")
	}

	#-------------------------------------------------------------------

	# xWaitForADDomain $DomainName
	# {
	# 	DomainName = $DomainName
	# 	RetryCount = $RetryCount
	# 	RetryIntervalSec = $RetryIntervalSec
	# 	DomainUserCredential = $AdminCreds
	# }

	# xComputer DomainJoin
	# {
	# 	Name       = $computername
	# 	DependsOn  = "[xWaitForADDomain]$DomainName"
	# 	DomainName = $DomainName
	# 	Credential = $credlookup["DomainJoin"]
	# }
    
	# # reboots after DJoin
	# xPendingReboot RebootForDJoin
	# {
	# 	Name                = 'RebootForDJoin'
	# 	DependsOn           = '[xComputer]DomainJoin'
    #     SkipWindowsUpdate   = $true
    #     SkipCcmClientSDK    = $true
    #     SkipComponentBasedServicing = $true
	# }
	#-------------------------------------------------------------------

	xTimeZone EasternStandardTime
    { 
        IsSingleInstance = 'Yes'
        TimeZone         = "Eastern Standard Time" 
    }

    #-------------------------------------------------------------------
    xDnsConnectionSuffix DomainSuffix
    {
        InterfaceAlias                 = "*Ethernet*"
        RegisterThisConnectionsAddress = $true
        ConnectionSpecificSuffix       = $DomainName
    }

    #-------------------------------------------------------------------

    Service ShellHWDetection
    {
        Name  = 'ShellHWDetection'
        State = 'Stopped'
    }
    #-------------------------------------------------------------------
    
    foreach ($PowerShellModule in $Node.PowerShellModulesPresent)
    {
        PSModule $PowerShellModule.Name
        {
            Name               = $PowerShellModule.Name
            InstallationPolicy = 'Trusted'
            RequiredVersion    = $PowerShellModule.RequiredVersion
            AllowClobber       = $true
        }
        $dependsonPowerShellModule += @("[PSModule]$($PowerShellModule.Name)")
    }

    #-------------------------------------------------------------
    foreach ($RegistryKey in $Node.RegistryKeyPresent)
    {
        
        Registry $RegistryKey.ValueName
        {
            Key       = $RegistryKey.Key
            ValueName = $RegistryKey.ValueName
            Ensure    = 'Present'
            ValueData = $RegistryKey.ValueData
            ValueType = $RegistryKey.ValueType
            Force     = $true
            PsDscRunAsCredential = $credlookup["DomainJoin"]
        }

        $dependsonRegistryKey += @("[Registry]$($RegistryKey.ValueName)")
    }
    #-------------------------------------------------------------------

    foreach ($disk in $Node.DisksPresent)
    {
        xDisk $disk.DriveLetter 
        {
            DiskID      = $disk.DiskID
            DriveLetter = $disk.DriveLetter
            AllocationUnitSize = 64KB
        }
        $dependsonDisksPresent += @("[xDisk]$($disk.DriveLetter)")
    }
    #-------------------------------------------------------------------

    #To clean up resource names use a regular expression to remove spaces, slashes an colons Etc.
    $StringFilter = "\W",''
    $StorageAccountName = Split-Path -Path $StorageAccountId -Leaf
    Write-Verbose -Message "User is: [$StorageAccountName]"
    $StorageCred = [pscredential]::new( $StorageAccountName , (ConvertTo-SecureString -String $StorageAccountKeySource -AsPlainText -Force))
        
    #-------------------------------------------------------------------     
    foreach ($File in $Node.DirectoryPresentSource)
    {
        $Name = ($File.filesSourcePath -f $StorageAccountName) -replace $StringFilter

        File $Name
        {
            SourcePath      = ($File.filesSourcePath -f $StorageAccountName)
            DestinationPath = $File.filesDestinationPath
            Ensure          = 'Present'
            Recurse         = $true
            Credential      = $StorageCred 
        }
        $dependsonDirectory += @("[File]$Name")
    } 

    #-------------------------------------------------------------
    if ($Node.WindowsFeatureSetPresent)
    {
        WindowsFeatureSet WindowsFeatureSetPresent
        {
            Ensure = 'Present'
            Name   = $Node.WindowsFeatureSetPresent
            Source = $Node.SXSPath
        }
    }

    # base install above - custom role install


    # ---------- SQL setup and install

    foreach ($User in $Node.ADUserPresent)
    {
        xADUser $User.UserName
        {
            DomainName  = $User.DomainName
            UserName    = $User.Username
            Description = $User.Description
            Enabled     = $True
            Password    = $credlookup["DomainJoin"]
            DomainController = $User.DomainController
            DomainAdministratorCredential = $credlookup["DomainJoin"]
        }
        $dependsonUser += @("[xADUser]$($User.Username)")
    }
    #-------------------------------------------------------------------
    $SQLSvcAccount = $credlookup["SQLService"].username
    Write-Warning -Message "user `$SQLSvcAccount is: $SQLSvcAccount" 
    #write-warning -Message $SQLSvcAccountCreds.GetNetworkCredential().password

    # Only required when using the Gallery image of SQL Server
    # Stop the default instance of SQLServer
    if (Test-Path -Path C:\SQLServerFull\)
    {
        ServiceSet defaultInstance
        {
            Name    = 'MSSQLSERVER','MSSQLServerOLAPService','SQLSERVERAGENT','SQLTELEMETRY','MSSQLFDLauncher','SSASTELEMETRY'
            State   = 'Stopped'
            StartupType = 'Disabled'
        }
    }

    # Note you need to open the firewall ports for both the probe and service ports
    # If you have multiple Availability groups for SQL, they need to run on different ports
    # If they share the same basic load balancer.
	# e.g. 1433,1434,1435
	# e.g. 59999,59998,59997
	xFirewall ProbePorts
    {
        Name      = 'ProbePorts'
        Action    = 'Allow'
        Direction = 'Inbound'
        LocalPort = 59999,59998,59997
        Protocol  = 'TCP'
    }

	xFirewall SQLPorts
    {
        Name      = 'SQLPorts'
        Action    = 'Allow'
        Direction = 'Inbound'
        LocalPort = 1433,1432,1431
        Protocol  = 'TCP'
        Profile   = 'Domain','Private'
    }

    foreach ($aoinfo in $SQLAOInfo)
    {
        $SQLInstanceName = $aoinfo.InstanceName
        Write-Warning "Installing SQL Instance: $SQLInstanceName"
        
        # https://msdn.microsoft.com/en-us/library/ms143547(v=sql.120).aspx
        # File Locations for Default and Named Instances of SQL Server
        SqlSetup xSqlServerInstall
        {
            SourcePath              = $Node.SQLSourcePath
            Action                  = 'Install'
            PsDscRunAsCredential    = $credlookup["DomainJoin"]
            InstanceName            = $SQLInstanceName
            Features                = $Node.SQLFeatures
            SQLSysAdminAccounts     = $SQLSvcAccount
            SQLSvcAccount           = $credlookup["SQLService"]
            AgtSvcAccount           = $credlookup["SQLService"]
            InstallSharedDir        = "F:\Program Files\Microsoft SQL Server"
            InstallSharedWOWDir     = "F:\Program Files (x86)\Microsoft SQL Server"
            InstanceDir             = "F:\Program Files\Microsoft SQL Server"
            InstallSQLDataDir       = "F:\MSSQL\Data"
            SQLUserDBDir            = "F:\MSSQL\Data"
            SQLUserDBLogDir         = "G:\MSSQL\Logs"
            SQLTempDBDir            = "H:\MSSQL\Data"
            SQLTempDBLogDir         = "H:\MSSQL\Temp" 
            SQLBackupDir            = "I:\MSSQL\Backup"
            DependsOn               = $dependsonUser
            UpdateEnabled           = "true"
            UpdateSource            = ".\Updates"
            SecurityMode            = "SQL"
            SAPwd                   = $credlookup["SQLService"]
        }

        foreach ($UserRightsAssignment in $Node.UserRightsAssignmentPresent)
        {
            $uraid = $UserRightsAssignment.identity | foreach { $_ -f $SQLInstanceName}

            UserRightsAssignment (($UserRightsAssignment.policy -replace $StringFilter) + ($uraid -replace $StringFilter))
            {
                Identity = $uraid
                Policy   = $UserRightsAssignment.policy
                PsDscRunAsCredential = $credlookup["DomainJoin"]
            }
    
            $dependsonUserRightsAssignment += @("[UserRightsAssignment]$($UserRightsAssignment.policy)")
        } 
			
        SQLServerMemory SetSQLServerMaxMemory
        {
            Ensure          = 'Present'
            DynamicAlloc    = $true
            ServerName      = $node.nodename
		    InstanceName    = $SQLInstanceName
            DependsOn       = '[SqlSetup]xSqlServerInstall'
            PsDscRunAsCredential = $credlookup["DomainJoin"]
        }

        SQLServerMaxDop SetSQLServerMaxDopToAuto
        {
            Ensure       = 'Present'
            DynamicAlloc = $true
            ServerName   = $node.nodename
    		InstanceName = $SQLInstanceName
            #MaxDop      = 8
            DependsOn    = '[SqlSetup]xSqlServerInstall'
        }
     
        #-------------------------------------------------------------------

        SqlWindowsFirewall xSqlServerInstall
        {
            SourcePath   = $Node.SQLSourcePath
            InstanceName = $SQLInstanceName
            Features     = $Node.SQLFeatures
            DependsOn    = '[SqlSetup]xSqlServerInstall'
        }

	    sqlservernetwork TCPPort1433
	    {
		    InstanceName = $SQLInstanceName
		    ProtocolName = 'TCP'
		    IsEnabled    = $true
            TCPPort      = '1433'
            RestartService = $true
	    }

	    foreach ($userLogin in $Node.SQLServerLogins)
	    {
		    SQLServerLogin $userLogin.Name
		    {
			    Ensure     = 'Present'
			    Name       = $userLogin.Name
			    LoginType  = 'WindowsUser'
			    ServerName = $computername
			    InstanceName = $SQLInstanceName
                DependsOn    = '[SqlSetup]xSqlServerInstall'
                PsDscRunAsCredential = $credlookup["DomainJoin"]
		    }
            $dependsonuserLogin += @("[SQLServerLogin]$($userLogin.Name)")
        }

	    foreach ($userRole in $Node.SQLServerRoles)
	    {
		    SQLServerRole $userRole.ServerRoleName
		    {
			    Ensure           = 'Present'
                ServerRoleName   = $userRole.ServerRoleName
                MembersToInclude = $userRole.MembersToInclude
			    ServerName        = $computername
			    InstanceName  = $SQLInstanceName
			    PsDscRunAsCredential = $credlookup["DomainJoin"]
			    DependsOn    = '[SqlSetup]xSqlServerInstall'
		    }
            $dependsonuserRoles += @("[SQLServerRole]$($userRole.ServerRoleName)")
        }

	    foreach ($userPermission in $Node.SQLServerPermissions)
	    {
		    # Add the required permissions to the cluster service login
		    SQLServerPermission $userPermission.Name
		    {
			    Ensure          = 'Present'
			    ServerName        = $computername
			    InstanceName    = $SQLInstanceName
			    Principal       = $userPermission.Name
			    Permission      = $userPermission.Permission
			    PsDscRunAsCredential = $credlookup["DomainJoin"]
			    DependsOn            = '[SqlSetup]xSqlServerInstall'
		    }
		    $dependsonSQLServerPermissions += @("[SQLServerPermission]$($userPermission.Name)")
	    }
        #-------------------------------------------------------------------

	    # Run and SQL scripts
        foreach ($Script in $Node.SQLServerScriptsPresent)
        {
	    $i = $Script.ServerInstance -replace $StringFilter
	    $Name = $Script.TestFilePath -replace $StringFilter
	    SQLScript ($i + $Name)
	    {
            ServerInstance = "$computername\$SQLInstanceName"
            SetFilePath    = $Script.SetFilePath
            GetFilePath    = $Script.GetFilePath
            TestFilePath   = $Script.TestFilePath
            PsDscRunAsCredential = $credlookup["DomainJoin"]   
	    }

	    $dependsonSQLServerScripts += @("[SQLScript]$($Name)")
	    }
        #-------------------------------------------------------------------
    }#Foreach $SQLAOInfo


    #-------------------------------------------------------------------
	# install any packages without dependencies
    foreach ($Package in $Node.SoftwarePackagePresent)
    {
	    $Name = $Package.Name -replace $StringFilter

	    xPackage $Name
	    {
		    Name            = $Package.Name
		    Path            = $Package.Path
		    Ensure          = 'Present'
		    ProductId       = $Package.ProductId
		    RunAsCredential = $credlookup["DomainJoin"]
            DependsOn       = $dependsonWebSites + '[SqlSetup]xSqlServerInstall'
            Arguments       = $Package.Arguments
	    }

	    $dependsonPackage += @("[xPackage]$($Name)")
	}

    # reboots after PackageInstall
    xPendingReboot PackageInstall
    {
        Name      = 'PackageInstall'
        DependsOn = $dependsonPackage
        SkipComponentBasedServicing = $true
        SkipWindowsUpdate = $true
    }

}

Node $AllNodes.Where{$env:computername -match $ClusterInfo.Primary}.NodeName
{
     # Allow this to be run against local or remote machine
    if($NodeName -eq "localhost") 
    {
        [string]$computername = $env:COMPUTERNAME
    }
    else {
        Write-Verbose $Nodename.GetType().Fullname
        [string]$computername = $Nodename
    } 
 
    Write-Warning -Message "PrimaryClusterNode"
    Write-Verbose -Message "Node is: [$($computername)]" -Verbose
    Write-Verbose -Message "NetBios is: [$NetBios]" -Verbose
    Write-Verbose -Message "DomainName is: [$DomainName]" -Verbose

    Write-Verbose -Message $computername -Verbose

	# Staging the Cluster Accounts and Always-On Accounts
    $ClusterName = $deployment + $ClusterInfo.CLNAME
    $ComputerAccounts = @($ClusterInfo.CLNAME) + ($SQLAOInfo.GroupName)
	
    foreach ($Computer in  $ComputerAccounts )
    {
        $cname = ($deployment + $Computer)
        write-warning ("computer: $cname")

        script ("CheckComputerAccount_" + $cname)  {
            PsDscRunAsCredential = $credlookup["DomainJoin"]
            GetScript = {
                $result = Get-ADComputer -Filter {Name -eq $using:cname} -ErrorAction SilentlyContinue
                @{
                    name           = "ComputerName"
                    value          = $result
                 }
            }#Get
            SetScript = {
                Write-warning "Creating computer account (disabled) $($using:cname)"
                New-ADComputer -Name $using:cname -Enabled $false -Description "Cluster SQL Availability Group" #-Path $using:ouname
				Start-Sleep -seconds 20
            }#Set 
            TestScript = {
                $result = Get-ADComputer -Filter {Name -eq $using:cname} -ErrorAction SilentlyContinue
                if ($result) 
                {
                    $true
                }
                else {
                    $false
                }

            }#Test
        }
    }

    foreach ($aoinfo in $SQLAOInfo)
    {
        # The AG Name in AD + DNS
        $cname = ($deployment + $aoinfo.GroupName)

#     SQL01 = "[{'InstanceName':'ADF_1','GroupName':'AG01','PrimaryAG':'SQL01','SecondaryAG':'SQL02', 'AOIP':'215','ProbePort':'59999'}]"

        # Prestage boht Computer Account and also DNS Record

		xDnsRecord $aoinfo.GroupName 
		{
			PsDscRunAsCredential = $credlookup["DomainJoin"]
            Name       = $cname
			Target     = ($NetworkID + $aoinfo.AOIP)   
			Type       = 'ARecord'
			Zone       = $DomainName
            DnsServer  = ($Deployment + 'AD01')
		}


        script ("ACL_" + $cname)  
        {
            PsDscRunAsCredential = $credlookup["DomainJoin"]
            GetScript = {
                $computer = Get-ADComputer -Filter {Name -eq $using:cname} -ErrorAction SilentlyContinue
                $computerPath = "AD:\" + $computer.DistinguishedName
                $ACL = Get-Acl -Path $computerPath
                $result = $ACL.Access | Where{$_.IdentityReference -match $using:ClusterName -and $_.ActiveDirectoryRights -eq "GenericAll"}
                @{
                    name           = "ACL"
                    value          = $result
                    }
            }#Get
            SetScript = {
                    
                $clusterSID = Get-ADComputer -Identity $using:ClusterName -ErrorAction Stop | Select-Object -ExpandProperty SID
                $computer = Get-ADComputer -Identity $using:cname
                $computerPath = "AD:\" + $computer.DistinguishedName
                $ACL = Get-Acl -Path $computerPath

                $R_W_E = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($clusterSID,'GenericAll','Allow')

                $ACL.AddAccessRule($R_W_E)
                Set-Acl -Path $computerPath -AclObject $ACL -Passthru -Verbose
            }#Set 
            TestScript = {
                $computer = Get-ADComputer -Filter {Name -eq $using:cname} -ErrorAction SilentlyContinue
                $computerPath = "AD:\" + $computer.DistinguishedName
                $ACL = Get-Acl -Path $computerPath
                $result = $ACL.Access | Where{$_.IdentityReference -match $using:ClusterName -and $_.ActiveDirectoryRights -eq "GenericAll"}
                if ($result) 
                {
                    $true
                }
                else {
                    $false
                }

            }#Test
        }#Script ACL
    }#Foreach Groupname

    ########################################
    script SetRSAMachineKeys
    {
        PsDscRunAsCredential = $credlookup["DomainJoin"]
        GetScript = {
            $rsa1 = Get-Item -path 'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys' | foreach {
                $_ | Get-NTFSAccess
            }
            $rsa2 = Get-Childitem -path 'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys'  | foreach {
                $_ | Get-NTFSAccess
            }
            @{directory = $rsa1; files = $rsa2}
        }
        SetScript = {
            Get-Item -path 'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys' | foreach {
    
                $_ | Set-NTFSOwner -Account BUILTIN\Administrators
                $_ | Clear-NTFSAccess -DisableInheritance
                $_ | Add-NTFSAccess -Account 'EVERYONE' -AccessRights ReadAndExecute -InheritanceFlags None -PropagationFlags NoPropagateInherit
                $_ | Add-NTFSAccess -Account BUILTIN\Administrators -AccessRights FullControl -InheritanceFlags None -PropagationFlags NoPropagateInherit
                $_ | Add-NTFSAccess -Account 'NT AUTHORITY\SYSTEM' -AccessRights FullControl -InheritanceFlags None -PropagationFlags NoPropagateInherit
                $_ | Get-NTFSAccess
            }

            Get-Childitem -path 'C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys'  | foreach {
                Write-Verbose $_.fullname -Verbose
                $_ | Clear-NTFSAccess -DisableInheritance 
                $_ | Set-NTFSOwner -Account BUILTIN\Administrators
                $_ | Add-NTFSAccess -Account 'EVERYONE' -AccessRights ReadAndExecute -InheritanceFlags None -PropagationFlags NoPropagateInherit
                $_ | Add-NTFSAccess -Account BUILTIN\Administrators -AccessRights FullControl -InheritanceFlags None -PropagationFlags NoPropagateInherit
                $_ | Add-NTFSAccess -Account 'NT AUTHORITY\SYSTEM' -AccessRights FullControl -InheritanceFlags None -PropagationFlags NoPropagateInherit
        
                $_ | Get-NTFSAccess
   
            }
        
        }
        TestScript = {
            $cluster = Get-Cluster -ea SilentlyContinue
            if ($cluster)
            {
                $true
            }
            else
            {
                $false
            }
        }
    }
        
    ########################################
    script MoveToPrimary
    {
        PsDscRunAsCredential = $credlookup["DomainJoin"]
        GetScript = {
            $Owner = Get-ClusterGroup -Name 'Cluster Group' -EA Stop | foreach OwnerNode
            @{Owner = $Owner}

        }#Get
        TestScript = {
            try {
                    $Owner = Get-ClusterGroup -Name 'Cluster Group' -EA Stop | foreach OwnerNode | Foreach Name

                    if ($Owner -eq $env:ComputerName)
                    {
                        Write-Warning -Message "Cluster running on Correct Node, continue"
                        $True
                    }
                    else
                    {
                        $False
                    }
            }#Try
            Catch {
                Write-Warning -Message "Cluster not yet enabled, continue"
                $True
            }#Catch
        }#Test
        SetScript = {
                
            Get-ClusterGroup -Name 'Cluster Group' -EA Stop | Move-ClusterGroup -Node $env:ComputerName -Wait 60

        }#Set
    }#MoveToPrimary

    xCluster SQLCluster
    {
        PsDscRunAsCredential          = $credlookup["DomainJoin"]
        Name                          = ($deployment + $ClusterInfo.CLNAME)
        StaticIPAddress               = $NetworkID + $ClusterInfo.CLIP
        DomainAdministratorCredential = $credlookup["DomainJoin"]
        DependsOn                     = '[script]MoveToPrimary'
    }

	xClusterQuorum CloudWitness
	{
		PsDscRunAsCredential    = $credlookup["DomainJoin"]
		IsSingleInstance        = 'Yes'
		type                    = 'NodeAndCloudMajority'
		Resource                = ($deployment + "sawitness").ToLower()
		StorageAccountAccessKey  = $sakwitness
	}

    foreach($Secondary in $ClusterInfo.Secondary) 
    {
        $clusterserver = ($deployment + $Secondary)
        script "AddNodeToCluster_$clusterserver" {
            PsDscRunAsCredential = $credlookup["DomainJoin"]
            GetScript = {
                $result = Get-ClusterNode
                @{key=$result}
            }
            SetScript = {
                Write-Verbose ("Adding Cluster Node: " + $using:clusterserver) -verbose
                Add-ClusterNode –Name $using:clusterserver -NoStorage 
                
            }
            TestScript = {
                    
                $result = Get-ClusterNode –Name $using:clusterserver -ea SilentlyContinue
                if($result) {
                    $true
                }
                else {
                    $false
                }
            }
        }
        $dependsonAddNodeToCluster += @("[script]$("AddNodeToCluster_$clusterserver")")
    }

}#Node-PrimaryFCI

Node $AllNodes.NodeName
{      
    # Allow this to be run against local or remote machine
    if($NodeName -eq "localhost") 
    {
        [string]$computername = $env:COMPUTERNAME
    }
    else 
    {
        Write-Verbose $Nodename.GetType().Fullname
        [string]$computername = $Nodename
    } 

    Write-Verbose -Message "Node is: [$($computername)]" -Verbose
    Write-Verbose -Message "NetBios is: [$NetBios]" -Verbose
    Write-Verbose -Message "DomainName is: [$DomainName]" -Verbose
    Write-Verbose -Message $computername -Verbose

    foreach ($aoinfo in $SQLAOInfo)
    {

        $SQLInstanceName = $aoinfo.InstanceName
        Write-Warning "Installing SQL Instance: $SQLInstanceName"
        
        $groupname = $aoinfo.GroupName
        $primary   = $deployment + $aoinfo.PrimaryAG
        $secondary = $deployment + $aoinfo.SecondaryAG

        $AOIP      = $NetworkID + $aoinfo.aoip  #'10.144.139.219'
        $ProbePort = $aoinfo.ProbePort          #"59999"
        $AOName    = ($deployment + $GroupName)  

        SqlServerEndpoint SQLEndPoint
        {
            Ensure               = "Present"
            Port                 = 5022
            EndPointName         = "Hadr_endpoint"
            ServerName           = $computername
            InstanceName         = $SQLInstanceName
            PsDscRunAsCredential = $credlookup["DomainJoin"]
        }

        # Start the DefaultMirrorEndpoint in the default instance
        SqlServerEndpointState StartEndpoint
        {
            ServerName           = $computername
            InstanceName         = $SQLInstanceName
            Name                 = "Hadr_endpoint"
            State                = 'Started'           
            DependsOn            = '[SqlServerEndpoint]SQLEndPoint'
            PsDscRunAsCredential = $credlookup["DomainJoin"]    
        }

        SqlAlwaysOnService SQLCluster
        {
            Ensure               = "Present"
            ServerName           = $computername
            InstanceName         = $SQLInstanceName
            RestartTimeout       = 360
            DependsOn            = '[SqlServerEndpointState]StartEndpoint'
            PsDscRunAsCredential = $credlookup["DomainJoin"]
        } 


        if ($computername -match $aoinfo.PrimaryAG) 
        {
            
            write-warning -message "Primary AO"
            write-warning -message "Computername: $Computername"
            write-warning -message "SQLInstanceName: $SQLInstanceName"
            write-warning -message "Groupname: $groupname"
            Write-warning -Message "AOIP: $AOIP"
            Write-warning -Message "AONAME: $AOName"
            Write-warning -Message "ProbePort: $ProbePort"
            Write-warning -Message ($computername + ".$DomainName")

            SqlDatabase $GroupName
            {
                Ensure           = 'Present'
                ServerName       = $computername
                InstanceName     = $SQLInstanceName
                Name             = $GroupName
            }

            SqlAG $groupname
            {
                ServerName            = $computername
                InstanceName          = $SQLInstanceName
                Name                  = $groupname
                AutomatedBackupPreference = 'Secondary'
                FailureConditionLevel = 'OnCriticalServerErrors'
                HealthCheckTimeout    = 600000

                AvailabilityMode      = 'SynchronousCommit'
                FailOverMode          = 'Automatic'
                ConnectionModeInPrimaryRole = 'AllowReadWriteConnections'
                ConnectionModeInSecondaryRole = 'AllowReadIntentConnectionsOnly'
                BackupPriority = 30
                EndpointHostName      = ($computername + ".$DomainName")
                PsDscRunAsCredential  = $credlookup["DomainJoin"]
            }

            script ("SeedingMode_" + $aoinfo.GroupName) 
            {
                PsDscRunAsCredential = $credlookup["DomainJoin"]
                GetScript = {
					$SQLInstanceName = $Using:SQLInstanceName
					if ($SQLInstanceName -eq "MSSQLServer"){$SQLInstanceName = 'Default'}

                    Import-Module -name SQLServer -Verbose:$False
                    $result = get-childitem -Path "SQLSERVER:\SQL\$using:primary\$SQLInstanceName\AvailabilityGroups\$using:groupname\AvailabilityReplicas\" -ea silentlycontinue | 
									where name -eq $using:primary\$SQLInstanceName | select *
                    if($result) {
                        @{key=$result}
                    }
                    else {
                        @{key="Not available"}
                    }
                }
                SetScript = {
					$SQLInstanceName = $Using:SQLInstanceName
					if ($SQLInstanceName -eq "MSSQLServer"){$SQLInstanceName = 'Default'}

                    Import-Module SQLServer -force -Verbose:$False
                    $result = get-childitem -Path "SQLSERVER:\SQL\$using:primary\$SQLInstanceName\AvailabilityGroups\$using:groupname\AvailabilityReplicas\" -ea silentlycontinue | 
									where name -eq $using:primary\$SQLInstanceName | select *

                    Write-Warning "PATH: $($result.pspath)"
                    Set-SqlAvailabilityReplica -SeedingMode "Automatic" -Path $result.pspath -Verbose
                }
                TestScript = {
					$SQLInstanceName = $Using:SQLInstanceName
					if ($SQLInstanceName -eq "MSSQLServer"){$SQLInstanceName = 'Default'}                    
					
					Import-Module -name SQLServer -force -Verbose:$False

                    $result = get-childitem -Path "SQLSERVER:\SQL\$using:primary\$SQLInstanceName\AvailabilityGroups\$using:groupname\AvailabilityReplicas\" -ea silentlycontinue | 
									where name -eq $using:primary\$SQLInstanceName | select *
                    
					write-warning "PATH: $($result.pspath)"
                    $result1 = get-item -Path $result.pspath -ea silentlycontinue | foreach SeedingMode

                    if($result1 -eq "Automatic") {
                        $true
                    }
                    else {
                        $false
                    }
                }
            }

            # Add DB to AOG, requires backup
            SqlAGDatabase ($groupname + "DB")
            {
                AvailabilityGroupName   = $groupname
                BackupPath              = "I:\MSSQL\Backup"
                DatabaseName            = $groupname
                InstanceName            = $SQLInstanceName
                ServerName              = $computername
                Ensure                  = 'Present'
                ProcessOnlyOnActiveNode = $true
                PsDscRunAsCredential    = $credlookup["DomainJoin"]
            }

            # Create the AO Listener for the ILB Probe (Final Step on Primary AG)
            script ("AAListener" + $GroupName)
            {
                #PsDscRunAsCredential = $credlookup["DomainJoin"]
                DependsOn = $dependsonSQLServerAOScripts
                GetScript = {
        
                    $GroupName = $using:GroupName
                    $AOName = $using:AOName
                    $result = Get-ClusterResource -Name $AOName -ea SilentlyContinue
                    @{key = $result}
                
                }
                SetScript = {
                    $AOIP = $using:AOIP
                    $ProbePort = $using:ProbePort
                    $GroupName = $using:GroupName
                    $AOName = $using:AOName
                    $IPResourceName = "${AOName}_IP"
                    $ClusterNetworkName = "Cluster Network 1"
                    write-warning "AOIP $AOIP"
                    write-warning "ProbePort $ProbePort"
                    write-warning "GroupName $GroupName"
                    write-warning "AOName $AOName"
                    write-warning "IPResourceName $IPResourceName"
                    
                    $nn = Get-ClusterResource -Name $AOName -ErrorAction SilentlyContinue | Stop-ClusterResource -Wait 20
                    
                    $nn = Add-ClusterResource -ResourceType "Network Name" -Name $AOName -Group $GroupName -ErrorAction SilentlyContinue
                    $ip = Add-ClusterResource -ResourceType "IP Address" -Name $IPResourceName -Group $GroupName -ErrorAction SilentlyContinue
                    Set-ClusterResourceDependency -Resource $AOName -Dependency "[$IPResourceName]"
                    Get-ClusterResource -Name $IPResourceName | Set-ClusterParameter -Multiple @{Address = $AOIP; ProbePort = $ProbePort; SubnetMask = "255.255.255.255"; Network = $ClusterNetworkName; EnableDhcp = 0}
                    Get-ClusterResource -Name $AOName | Set-ClusterParameter -Multiple @{"Name" = "$AOName"}
                    Get-ClusterResource -Name $AOName | Start-ClusterResource -Wait 20
                    Get-ClusterResource -Name $IPResourceName | Start-ClusterResource -Wait 20
        
                }
                TestScript = {
                    $AOName = ($using:AOName)
                    write-warning  "Cluster Resource Name Is ${AOName}_IP"
                    $n = Get-ClusterResource -Name "${AOName}_IP" -ea SilentlyContinue  
                                
                    if ($n.Name -eq "${AOName}_IP" -and $n.state -eq "Online")
                    {
                        $true
                    }
                    else
                    {
                        $false
                    }
                }
            }

        }#IfPrimaryAO
        elseif($computername -match $aoinfo.secondarynode )
        {

            write-warning -message "SecondaryAO"
            write-warning -message "Computername:$Computername"
            write-warning -message "SQLInstanceName:$SQLInstanceName"
            write-warning -message "Groupname:$groupname"
            Write-warning -Message "AONAME: $AOName"
            Write-warning -Message ($computername + ".$DomainName")
            
            SqlWaitForAG $GroupName
            {
                Name             = $groupname
                RetryIntervalSec = 30
                RetryCount       = 40
                
            }
            $dependsonwaitAG += @("[SqlWaitForAG]$groupname")
    
            WaitForAll $GroupName 
            {
                NodeName = $primary
                ResourceName = "[SqlAG]$($GroupName)"
                RetryCount = $RetryCount
                RetryIntervalSec = $RetryIntervalSec
            }
    
            SqlAGReplica ($groupname + "AddReplica")
            {
                PsDscRunAsCredential       = $credlookup["DomainJoin"]
                Ensure                     = 'Present'
                Name                       = "$computername\$SQLInstanceName"
                AvailabilityGroupName      = $groupname
                ServerName                 = $computername
                InstanceName               = $SQLInstanceName
                PrimaryReplicaServerName   = $primary
                PrimaryReplicaInstanceName = $SQLInstanceName
                AvailabilityMode              = 'SynchronousCommit'
                FailOverMode                  = 'Automatic'
                ConnectionModeInPrimaryRole   = 'AllowReadWriteConnections'
                ConnectionModeInSecondaryRole = 'AllowReadIntentConnectionsOnly'
                BackupPriority                = 30
                EndpointHostName              = ($computername + ".$DomainName")

            }
            
            script ("SeedingMode_" + $deployment + $aoinfo.GroupName) 
            {
                DependsOn = ('[SqlAGReplica]' + $groupname + "AddReplica")
                PsDscRunAsCredential = $credlookup["DomainJoin"]
                GetScript = {
					$SQLInstanceName = $Using:SQLInstanceName
					if ($SQLInstanceName -eq "MSSQLServer"){$SQLInstanceName = 'Default'}

                    Import-Module -name SQLServer -Verbose:$False
                    #$result = get-item -Path      "SQLSERVER:\SQL\$using:primary\$SQLInstanceName\AvailabilityGroups\$using:groupname\AvailabilityReplicas\$using:secondary\$SQLInstanceName" -ea silentlycontinue | select *
                        $result = get-childitem -Path "SQLSERVER:\SQL\$using:primary\$SQLInstanceName\AvailabilityGroups\$using:groupname\AvailabilityReplicas\" -ea silentlycontinue | where name -eq $using:secondary\$SQLInstanceName | select *
                        write-warning "PATH: $($result.pspath)"
                    if($result) {
                        @{key=$result}
                    }
                    else {
                        @{key="Not available"}
                    }
                }
                SetScript = {
					$SQLInstanceName = $Using:SQLInstanceName
					if ($SQLInstanceName -eq "MSSQLServer"){$SQLInstanceName = 'Default'}

                    Import-Module SQLServer -force -Verbose:$False
                    #Get-PSProvider -Verbose
                    #get-psdrive -Verbose

                    $p1 = "SQLSERVER:\SQL\$using:secondary\$SQLInstanceName\AvailabilityGroups\$using:groupname"
                    write-warning "PATH: $p1"
                    Grant-SqlAvailabilityGroupCreateAnyDatabase -path $p1

                    $result = get-childitem -Path "SQLSERVER:\SQL\$using:primary\$SQLInstanceName\AvailabilityGroups\$using:groupname\AvailabilityReplicas\" -ea silentlycontinue | where name -eq $using:secondary\$SQLInstanceName | select *
                        write-warning "PATH: $($result.pspath)"

                    # $p = "SQLSERVER:\SQL\$using:primary\$SQLInstanceName\AvailabilityGroups\$using:groupname\AvailabilityReplicas\$using:secondary\$SQLInstanceName"
                    # write-warning "PATH: $p"
                    
                    Set-SqlAvailabilityReplica -SeedingMode "Automatic" -Path $result.pspath -Verbose
                                                                                
                    #Set-SqlAvailabilityReplica -SeedingMode Automatic -Path "SQLSERVER:\SQL\$env:computername\DEFAULT\AvailabilityGroups\$using:groupname\AvailabilityReplicas\$using:secondary" 
                
                }
                TestScript = {
					$SQLInstanceName = $Using:SQLInstanceName
					if ($SQLInstanceName -eq "MSSQLServer"){$SQLInstanceName = 'Default'}

                    Import-Module -name SQLServer -force -Verbose:$False
                    #$p = "SQLSERVER:\SQL\$using:primary\$SQLInstanceName\AvailabilityGroups\$using:groupname\AvailabilityReplicas\$using:secondary\$SQLInstanceName"
                    #write-warning "PATH: $p"
                    $result = get-childitem -Path "SQLSERVER:\SQL\$using:primary\$SQLInstanceName\AvailabilityGroups\$using:groupname\AvailabilityReplicas\" -ea silentlycontinue | where name -eq $using:secondary\$SQLInstanceName | foreach SeedingMode
                        write-warning "PATH: $($result.pspath)"
                    #$result1 = get-item -Path $p -ea silentlycontinue | foreach SeedingMode
                    #$result2 = get-item -Path "SQLSERVER:\SQL\$env:computername\DEFAULT\AvailabilityGroups\$using:groupname\AvailabilityReplicas\$using:secondary" -ea silentlycontinue | foreach SeedingMode
                    if($result -eq "Automatic") {
                        $true
                    }
                    else {
                        $false
                    }
                }
            }#Script
        }#SecondaryAG

    }#Foreach(AOInfo)
}#Node

}#Main

# used for troubleshooting
# F5 loads the configuration and starts the push

#region The following is used for manually running the script, breaks when running as system
if ((whoami) -notmatch 'system')
{
    Write-Warning -Message "no testing in prod !!!"
    if ($cred)
    {
        Write-Warning -Message "Cred is good"
    }
    else
    {
        $Cred = get-credential localadmin
    }

    #  if ($sak)
    #  {
    #      Write-Warning -Message "StorageAccountKey is good"
    #  }
    #  else
    #  {
    #      $sak = Read-Host -prompt "Enter the StorageAccountKey to download files"
    #  }

    # if($djcred) {
	# 	Write-Warning -Message "Domain Join Cred is good"
	# }
	# else {
	# 	$a = Read-Host -AsSecureString -prompt "DomainJoinUser pass:"
	# 	$djcred = [pscredential]::new('consoso\localadmin',$a)
	# }

    # if($sqlcred) {
	# 	Write-Warning -Message "SQL Account Cred is good"
	# }
	# else {
	# 	$a = Read-Host -AsSecureString -prompt "DomainSQLUser pass:"
	# 	$sqlcred = [pscredential]::new('Contoso\Localadmin',$a)
	# }

    # Set the location to the DSC extension directory
    $DSCdir = ($psISE.CurrentFile.FullPath | split-Path)
    if (Test-Path -Path $DSCdir -ErrorAction SilentlyContinue)
    {
        Set-Location -Path $DSCdir -ErrorAction SilentlyContinue
    }
}
else
{
    Write-Warning -Message "running as system"
    break
}
#endregion

dir .\SQLServers -Filter *.mof -ea SilentlyContinue | Remove-Item -ea SilentlyContinue

$aoinfo = @{
    SQL01 = "[{'InstanceName':'ADF_1','GroupName':'AG01','PrimaryAG':'SQL01','SecondaryAG':'SQL02', 'AOIP':'215','ProbePort':'59999'}]"
    SQL02 = "[{'InstanceName':'ADF_1','GroupName':'AG01','PrimaryAG':'SQL01','SecondaryAG':'SQL02'}]"
    SQL03 = "[{'InstanceName':'ADF_2','GroupName':'AG02','PrimaryAG':'SQL03','SecondaryAG':'SQL04', 'AOIP':'213','ProbePort':'59999'}]"
    SQL04 = "[{'InstanceName':'ADF_2','GroupName':'AG02','PrimaryAG':'SQL03','SecondaryAG':'SQL04'}]"
}

$ClusterInfo = @{
    SQL01 = "{'CLNAME':'CLS01','CLIP':'216','Primary':'SQL01','Secondary':['SQL02']}"
    SQL02 = "{'CLNAME':'CLS01','CLIP':'216','Primary':'SQL01','Secondary':['SQL02']}"
    SQL03 = "{'CLNAME':'CLS02','CLIP':'214','Primary':'SQL03','Secondary':['SQL04']}"
    SQL04 = "{'CLNAME':'CLS02','CLIP':'214','Primary':'SQL03','Secondary':['SQL04']}"
}

# AZE2 ADF D 1
$depid   = $env:computername.substring(8,1)  # 1
$dep     = $env:computername.substring(0,9)  # AZE2ADFD1
$cmp     = $env:computername -replace $dep,""
$network = 143 - $Depid
$Net     = "10.0.${network}."
$a = $aoinfo[$cmp]
$b = $ClusterInfo[$cmp]
$AO = "{'aoinfo': $a , 'ClusterInfo': $b}"

$Params = @{
 ConfigurationData       =  ".\*-ConfigurationData.psd1"
 AppInfo                 = $AO
 AdminCreds              = $cred
 #DomainJoinCreds         = $djcred
 #DomainSQLCreds          = $sqlcred
 #StorageAccountKeySource = $sak
 Deployment              = $dep
 networkID               = $Net 
 Verbose                 = $true
}

# Compile the MOFs
SQLServers @Params

# Set the LCM to reboot
Set-DscLocalConfigurationManager -Path .\SQLServers -Force 

# Push the configuration
Start-DscConfiguration -Path .\SQLServers -Wait -Verbose -Force

# delete mofs after push
dir .\SQLServers -Filter *.mof -ea SilentlyContinue | Remove-Item -ea SilentlyContinue

break

Get-DscLocalConfigurationManager

Start-DscConfiguration -UseExisting -Wait -Verbose -Force

Get-DscConfigurationStatus -All

$result = Test-DscConfiguration -Detailed
$result.resourcesnotindesiredstate
$result.resourcesindesiredstate