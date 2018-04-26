Configuration AppServers
{
    Param ( 
        [String]$DomainName = 'Contoso.com',
        [PSCredential]$AdminCreds,
        [Int]$RetryCount = 30,
        [Int]$RetryIntervalSec = 120,
        [String]$ThumbPrint,
        [String]$StorageAccountId,
        [String]$Deployment,
        [String]$NetworkID,
        [String]$AppInfo
        )


    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xComputerManagement
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xStorage
    Import-DscResource -ModuleName xPendingReboot
    Import-DscResource -ModuleName xWebAdministration
    Import-DscResource -ModuleName xPSDesiredStateConfiguration 
    Import-DscResource -ModuleName SecurityPolicyDSC    
    Import-DscResource -ModuleName xTimeZone
    Import-DscResource -ModuleName xWindowsUpdate 
    Import-DscResource -ModuleName xDSCFirewall
    Import-DscResource -ModuleName xNetworking
    Import-DscResource -ModuleName xSqlServer  
	Import-DscResource -ModuleName PackageManagementProviderResource	
    Import-DscResource -ModuleName xRemoteDesktopSessionHost
    Import-DscResource -ModuleName AccessControlDsc

    
        # -------- MSI lookup for storage account keys to download files and set Cloud Witness
        $response = Invoke-WebRequest -UseBasicParsing -Uri http://169.254.169.254/metadata/identity/oauth2/token -Method GET -Body @{resource="https://management.azure.com/"} -Headers @{Metadata="true"}
        $ArmToken = $response.Content | ConvertFrom-Json | Foreach access_token
        $Params = @{ Method = 'POST'; UseBasicParsing = $true; ContentType = "application/json"; Headers = @{ Authorization ="Bearer $ArmToken"} }

        # Global assets to download files
        $Params['Uri'] =  "https://management.azure.com{0}/{1}/?api-version=2016-01-01" -f $StorageAccountId,'listKeys'
        $storageAccountKeySource = (Invoke-WebRequest @Params).content | ConvertFrom-Json | Foreach Keys | Select -first 1 | foreach Value
        Write-Verbose "SAK Global: $storageAccountKeySource" -Verbose      
	
    [PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("$DomainName\$(($AdminCreds.UserName -split '\\')[-1])", $AdminCreds.Password)

    node $AllNodes.NodeName
    {
        if($NodeName -eq "localhost") 
        {
            [string]$computername = $env:COMPUTERNAME
        }
        else 
        {
            Write-Verbose $Nodename.GetType().Fullname
            [string]$computername = $Nodename
        } 
        Write-Verbose -Message $computername -Verbose

        LocalConfigurationManager
        {
            ActionAfterReboot   = 'ContinueConfiguration'
            ConfigurationMode   = 'ApplyAndMonitor'
            RebootNodeIfNeeded  = $True
            AllowModuleOverWrite = $true
        }


        #-------------------------------------------------------------------
        xTimeZone EasternStandardTime
        { 
            IsSingleInstance = 'Yes'
            TimeZone         = "Eastern Standard Time" 
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
        if ($Node.WindowsFeatureSetPresent)
        {
            WindowsFeatureSet WindowsFeatureSetPresent
            {
                Ensure = 'Present'
                Name   = $Node.WindowsFeatureSetPresent
               #Source = $Node.SXSPath
            }
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

        #-------------------------------------------------------------------
        if ($Node.ServiceSetStopped)
        {
            ServiceSet ServiceSetStopped
            {
                Name  = $Node.ServiceSetStopped
                State = 'Stopped'
            }
        }
        #-------------------------------------------------------------------
        foreach ($disk in $Node.DisksPresent)
        {
            xDisk $disk.DriveLetter 
            {
                DiskID  = $disk.DiskID
                DriveLetter = $disk.DriveLetter
            }
            $dependsonDisksPresent += @("[xDisk]$($disk.DriveLetter)")
        }
        #-------------------------------------------------------------------

        # xWaitForADDomain $DomainName
        # {
        #     DependsOn  = $dependsonFeatures
        #     DomainName = $DomainName
        #     RetryCount = $RetryCount
        #     RetryIntervalSec = $RetryIntervalSec
        #     DomainUserCredential = $AdminCreds
        # }

        # xComputer DomainJoin
        # {
        #     Name       = $computername
        #     DependsOn  = "[xWaitForADDomain]$DomainName"
        #     DomainName = $DomainName
        #     Credential = $DomainCreds
        # }
    
        #------------------------------------------------------------
        # remove windows update for now, takes too long to apply updates
        # Updated reboots to skip checking windows update paths
        # 
        #  xWindowsUpdateAgent MuSecurityImportant
        #  {
        #      IsSingleInstance = 'Yes'
        #      UpdateNow        = $true
        #      Category         = @('Security')
        #      Source           = 'MicrosoftUpdate'
        #      Notifications    = 'Disabled'
        #  }
        #  # Checking Windows Firewall
	
        Service WindowsFirewall
        {
            Name        = "MPSSvc"
            StartupType = "Automatic"
            State       = "Running"
        }

        # # reboots after DJoin and Windows Updates
        # xPendingReboot RebootForDJoin
        # {
        #     Name      = 'RebootForDJoin'
        #     DependsOn = '[xComputer]DomainJoin'#,'[xWindowsUpdateAgent]MuSecurityImportant'
        #     SkipComponentBasedServicing = $True
        #     SkipWindowsUpdate = $True 
        # }

        # base install above - custom role install
        #-------------------------------------------------------------------

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
                PsDscRunAsCredential = $DomainCreds
            }

            $dependsonRegistryKey += @("[Registry]$($RegistryKey.ValueName)")
        }
    
        #-------------------------------------------------------------------

        foreach ($User in $Node.ADUserPresent)
        {
			
            xADUser $User.UserName
            {
                DomainName  = $User.DomainName
                UserName    = $User.Username
                Description = $User.Description
                Enabled     = $True
                Password    = $DomainCreds
                #DomainController = $User.DomainController
                DomainAdministratorCredential = $DomainCreds
		
            }

            $dependsonUser += @("[xADUser]$($User.Username)")
        }
        #-------------------------------------------------------------------

        foreach ($UserRightsAssignment in $Node.UserRightsAssignmentPresent)
        {
            UserRightsAssignment $UserRightsAssignment.policy
            {
                Identity     = $UserRightsAssignment.identity
                Policy       = $UserRightsAssignment.policy       
            }
            $dependsonUserRightsAssignment += @("[UserRightsAssignment]$($UserRightsAssignment.policy)")
        }
        #-------------------------------------------------------------------
        #To clean up resource names use a regular expression to remove spaces, slashes an colons Etc.
        $StringFilter = "\W",""

        foreach ($Group in $Node.GroupMemberPresent)
        {
            $Name = $Group.MemberstoInclude -replace $StringFilter

            xGroup $Name
            {
                GroupName     = $Group.GroupName
                MemberstoInclude       = $Group.MemberstoInclude       
            }

            $dependsonGroup += @("[xGroup]$($Group.GroupName)")
        }

		#-------------------------------------------------------------

		foreach ($PowerShellModule in $Node.PowerShellModulesPresent)
		{
		    PSModule $PowerShellModule
			{
				Name                 = $PowerShellModule
				InstallationPolicy   = 'Trusted'
                PsDscRunAsCredential = $AdminCreds
                AllowClobber         = $true
			}
		    $dependsonPowerShellModule += @("[PSModuleResource]$PowerShellModule")
		}

        #-------------------------------------------------------------------
        foreach ($userLogin in $Node.SQLServerLogins)
        {
            xSQLServerLogin $userLogin.Name
            {
                Ensure				 = 'Present'
                Name				 = $userLogin.Name
                LoginType			 = 'WindowsUser'
                SQLServer			 = $Node.SQLServer
                SQLInstanceName		 = $Node.InstanceName
                DependsOn			 = $dependsonPowerShellModule
				PsDscRunAsCredential = $SQLSvcAccountCreds
            }
            $dependsonuserLogin += @("[xSQLServerLogin]$($userLogin.Name)")
        }

        #-------------------------------------------------------------------
        foreach ($userRole in $Node.SQLServerRoles)
        {
            xSQLServerRole $userRole.ServerRoleName
            {
                Ensure               = 'Present'
                ServerRoleName       = $userRole.ServerRoleName
                MembersToInclude     = $userRole.MembersToInclude
                SQLServer			 = $Node.SQLServer
                SQLInstanceName      = $Node.InstanceName
                DependsOn            = $dependsonPowerShellModule
				PsDscRunAsCredential = $SQLSvcAccountCreds
            }
            $dependsonuserRoles += @("[xSQLServerRole]$($userRole.ServerRoleName)")
        }

        #-------------------------------------------------------------------
        foreach ($userPermission in $Node.SQLServerPermissions)
        {
            # Add the required permissions to the cluster service login
            xSQLServerPermission $userPermission.Name
            {
                Ensure				 = 'Present'
                NodeName			 = $Node.SQLServer
                InstanceName		 = $Node.InstanceName
                Principal			 = $userPermission.Name
                Permission			 = $userPermission.Permission
                DependsOn            = $dependsonPowerShellModule
				PsDscRunAsCredential = $SQLSvcAccountCreds
            }
            $dependsonSQLServerPermissions += @("[xSQLServerPermission]$($userPermission.Name)")
        }
        #-------------------------------------------------------------------	

        #-------------------------------------------------------------------
        if ($Node.ServiceSetStarted)
        {
            ServiceSet ServiceSetStarted
            {
                Name        = $Node.ServiceSetStarted
                State       = 'Running'
                StartupType = 'Automatic'
                DependsOn   = @('[WindowsFeatureSet]WindowsFeatureSetPresent') + $dependsonRegistryKey
            }
        }

        #-------------------------------------------------------------------
        $StorageAccountName = Split-Path -Path $StorageAccountId -Leaf
        Write-Verbose -Message "User is: [$StorageAccountName]"
        $StorageCred = [pscredential]::new( $StorageAccountName , (ConvertTo-SecureString -String $StorageAccountKeySource -AsPlainText -Force))
    
        #Set environment path variables
        #-------------------------------------------------------------------

        foreach ($EnvironmentPath in $Node.EnvironmentPathPresent)
        {
            $Name = $EnvironmentPath -replace $StringFilter
            Environment $Name
            {
                Name    = "Path"
                Value   = $EnvironmentPath
                Path    = $true
            }
            $dependsonEnvironmentPath += @("[Environment]$Name")
        }

        #-------------------------------------------------------------------

        foreach ($Dir in $Node.DirectoryPresent)
        {
            $Name = $Dir -replace $StringFilter
            File $Name
            {
                DestinationPath = $Dir
                Type            = 'Directory'
            }
            $dependsonDir += @("[File]$Name")
        }

        #-------------------------------------------------------------------     
		foreach ($File in $Node.DirectoryPresentSource)
		{
			$Name = ($File.filesSourcePath -f $StorageAccountName) -replace $StringFilter
			File $Name
			{
				SourcePath      = ($File.filesSourcePath -f $StorageAccountName)
				DestinationPath = $File.filesDestinationPath
				Ensure          = 'Present'
				Recurse         = $true
				Credential      = $StorageCred  
			}
			$dependsonDirectory += @("[File]$Name")
		}

        #-----------------------------------------
        foreach ($WebSite in $Node.WebSiteAbsent)
        {
            $Name =  $WebSite.Name -replace ' ',''
            xWebsite $Name 
            {
                Name         = $WebSite.Name
                Ensure       = 'Absent'
                State        = 'Stopped'
                PhysicalPath = 'C:\inetpub\wwwroot'
                DependsOn    = $dependsonFeatures
            }
            $dependsonWebSitesAbsent += @("[xWebsite]$Name")
        }

        #-------------------------------------------------------------------
        foreach ($AppPool in $Node.WebAppPoolPresent)
        { 
            $Name = $AppPool.Name -replace $StringFilter

            xWebAppPool $Name 
            {
                Name                  = $AppPool.Name
                State                 = 'Started'
                autoStart             = $true
                DependsOn             = '[ServiceSet]ServiceSetStarted'
                managedRuntimeVersion = $AppPool.Version
                identityType          = 'SpecificUser'
                Credential            = $DomainCreds
                enable32BitAppOnWin64 = $AppPool.enable32BitAppOnWin64
            }
            $dependsonWebAppPool += @("[xWebAppPool]$Name")
        }
        #-------------------------------------------------------------------


        foreach ($WebSite in $Node.WebSitePresent)
        {
            $Name = $WebSite.Name -replace $StringFilter
		  
            xWebsite $Name 
            {
                Name            = $WebSite.Name
                ApplicationPool = $WebSite.ApplicationPool
                PhysicalPath    = $Website.PhysicalPath
                State           = 'Started'
                DependsOn       = $dependsonWebAppPools
                BindingInfo = foreach ($Binding in $WebSite.BindingPresent)
                {
                    MSFT_xWebBindingInformation  
                        {  
                            Protocol  = $binding.Protocol
                            Port      = $binding.Port
                            IPAddress = $binding.IpAddress
                            HostName  = $binding.HostHeader
                            CertificateThumbprint = $ThumbPrint
                            CertificateStoreName = "MY"   
                        }
                }
            }
            $dependsonWebSites += @("[xWebsite]$Name")
        }

        #------------------------------------------------------
        foreach ($WebVirtualDirectory in $Node.VirtualDirectoryPresent)
        {
            xWebVirtualDirectory $WebVirtualDirectory.Name
            {
                Name                 = $WebVirtualDirectory.Name
                PhysicalPath         = $WebVirtualDirectory.PhysicalPath
                WebApplication       = $WebVirtualDirectory.WebApplication
                Website              = $WebVirtualDirectory.Website
                PsDscRunAsCredential = $DomainCreds
                Ensure               = 'Present'
                DependsOn            = $dependsonWebSites
            }
            $dependsonWebVirtualDirectory += @("[xWebVirtualDirectory]$($WebVirtualDirectory.name)")
        }

        # set virtual directory creds
        foreach ($WebVirtualDirectory in $Node.VirtualDirectoryPresent)
        {
            $vdname	= $WebVirtualDirectory.Name
            $wsname	= $WebVirtualDirectory.Website
            $pw		= $DomainCreds.GetNetworkCredential().Password
            $Domain	= $DomainCreds.GetNetworkCredential().Domain
            $UserName = $DomainCreds.GetNetworkCredential().UserName

            script $vdname  {
                DependsOn = $dependsonWebVirtualDirectory 
                
                GetScript = {
                    Import-Module -Name "webadministration"
                    $vd = Get-WebVirtualDirectory -site  $using:wsname -Name $vdname
                    @{
                        path           = $vd.path
                        physicalPath   = $vd.physicalPath
                        userName       = $vd.userName
                     }
                }#Get
                SetScript = {
                    Import-Module -Name "webadministration"
                    Set-ItemProperty -Path "IIS:\Sites\$using:wsname\$using:vdname" -Name userName -Value "$using:domain\$using:UserName"
                    Set-ItemProperty -Path "IIS:\Sites\$using:wsname\$using:vdname" -Name password -Value $using:pw
                }#Set 
                TestScript = {
                    Import-Module -Name "webadministration"
                    Write-warning $using:vdname
                    $vd = Get-WebVirtualDirectory -site  $using:wsname -Name $using:vdname
                    if ($vd.userName -eq  "$using:domain\$using:UserName") {
                        $true
                    }
                    else {
                        $false
                    }

                }#Test
            }#[Script]VirtualDirCreds
        }
            
        #------------------------------------------------------
        foreach ($WebApplication in $Node.WebApplicationsPresent)
        {
            xWebApplication $WebApplication.Name
            {
                Name         = $WebApplication.Name
                PhysicalPath = $WebApplication.PhysicalPath
                WebAppPool   = $WebApplication.ApplicationPool
                Website      = $WebApplication.Site
                Ensure       = 'Present'
                DependsOn    = $dependsonWebSites
            }
            $dependsonWebApplication += @("[xWebApplication]$($WebApplication.name)")
        }

        #-------------------------------------------------------------------
        # Run and SQL scripts
        foreach ($Script in $Node.SQLServerScriptsPresent)
        {
            $i = $Script.ServerInstance -replace $StringFilter
            $Name = $Script.TestFilePath -replace $StringFilter
            xSQLServerScript ($i + $Name)
            {
                ServerInstance = $Script.ServerInstance
                SetFilePath    = $Script.SetFilePath
                GetFilePath    = $Script.GetFilePath
                TestFilePath   = $Script.TestFilePath
                PsDscRunAsCredential = $DomainCreds   
            }

            $dependsonSQLServerScripts += @("[xSQLServerScript]$($Name)")
        }

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
                RunAsCredential = $DomainCreds
                DependsOn       = $dependsonDirectory
                Arguments       = $Package.Arguments
            }

            $dependsonPackage += @("[xPackage]$($Name)")
        }

        #-------------------------------------------------------------------

        # install packages that need to check registry path E.g. .Net frame work
        foreach ($Package in $Node.SoftwarePackagePresentRegKey)
        {
              $Name = $Package.Name -replace $StringFilter
              xPackage $Name
              {
                     Name            = $Package.Name
                     Path            = $Package.Path
                     Ensure          = 'Present'
                     ProductId       = $Package.ProductId
                     DependsOn       = $dependsonDirectory + $dependsonArchive
                     Arguments       = $Package.Arguments
                     RunAsCredential       = $DomainCreds 
                     CreateCheckRegValue        = $true 
                     InstalledCheckRegHive      = $Package.RegHive
                     InstalledCheckRegKey       = $Package.RegKey
                     InstalledCheckRegValueName = $Package.RegValueName
                     InstalledCheckRegValueData = $Package.RegValueData
              }

              $dependsonPackageRegKey += @("[xPackage]$($Name)")
         }

        #-------------------------------------------------------------------
        # install new services
        foreach ($NewService in $Node.NewServicePresent)
        {
            $Name = $NewService.Name -replace $StringFilter
            xService $Name
            {
                Name            = $NewService.Name
                Path            = $NewService.Path
                Ensure          = 'Present'
                Credential      = $DomainCreds
                Description     = $NewService.Description 
                StartupType     = $NewService.StartupType
                State           = $NewService.State
                DependsOn       = $apps 
            }
        
            $dependsonService += @("[xService]$($Name)")
        }

        #------------------------------------------------------
	
        # Reboot after Package Install

        xPendingReboot RebootForPackageInstall
        {
            Name      = 'RebootForPackageInstall'
            DependsOn = $dependsonPackage
            SkipComponentBasedServicing = $True
            SkipWindowsUpdate = $True 
        }
    }
}#Main

# used for troubleshooting
# F5 loads the configuration and starts the push

#region The following is used for manually running the script, breaks when running as system
if ((whoami) -match 'localadmin')
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

    # if ($sak)
    # {
    #     Write-Warning -Message "StorageAccountKey is good"
    # }
    # else
    # {
    #     $sak = Read-Host -prompt "Enter the StorageAccountKey to download files"
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

Get-ChildItem -Path .\AppServers -Filter *.mof -ea 0 | Remove-Item 

$Params = @{
 ConfigurationData       =  ".\*-ConfigurationData.psd1" 
 AdminCreds              = $cred 
 deployment              = $env:computername.substring(0,9) #AZE2ADFD5 (AZE2ADFD5JMP01)
 Verbose                 = $true
}

# Compile the MOFs
 AppServers @Params

# Set the LCM to reboot
Set-DscLocalConfigurationManager -Path .\AppServers -Force 

# Push the configuration
Start-DscConfiguration -Path .\AppServers -Wait -Verbose -Force

# Delete the mofs directly after the push
Get-ChildItem -Path .\AppServers -Filter *.mof -ea 0 | Remove-Item 
break

Get-DscLocalConfigurationManager

Start-DscConfiguration -UseExisting -Wait -Verbose -Force

Get-DscConfigurationStatus -All

Test-DscConfiguration
Test-DscConfiguration -ReferenceConfiguration .\main\LocalHost.mof

$r = Test-DscConfiguration -detailed
$r.ResourcesNotInDesiredState
$r.ResourcesInDesiredState


Install-Module -name xComputerManagement,xActiveDirectory,xStorage,xPendingReboot,xWebAdministration,xPSDesiredStateConfiguration,SecurityPolicyDSC  -Force

$ComputerName = $env:computerName

icm $ComputerName {
    Get-Module -ListAvailable -Name  xComputerManagement,xActiveDirectory,xStorage,xPendingReboot,xWebAdministration,xPSDesiredStateConfiguration,SecurityPolicyDSC | foreach {
        $_.ModuleBase | Remove-Item -Recurse -Force
    }
    Find-Package -ForceBootstrap -Name xComputerManagement
    Install-Module -name xComputerManagement,xActiveDirectory,xStorage,xPendingReboot,xWebAdministration,xPSDesiredStateConfiguration,SecurityPolicyDSC  -Force -Verbose
}


#test-wsman
#get-service winrm | restart-service -PassThru
#enable-psremoting -force
#ipconfig /all
#ping azgateway200 -4
#ipconfig /flushdns
#Install-Module -Name xDSCFirewall,xWindowsUpdate
#Install-module -name xnetworking