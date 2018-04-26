#
# ConfigurationDataSQL.psd1
#

@{ 
AllNodes = @( 
    @{ 
        NodeName					= "*" 
		PSDscAllowDomainUser		= $true
		PSDscAllowPlainTextPassword = $true
                
        SQLSourcePath				= "C:\SQLServerFull\"
        AdminAccount				= "Contoso\localadmin"  
 
        SQLVersion                  = 'MSSQL13'
        SQLFeatures					= "SQLENGINE,FullText"

		SQLLarge                    = $true

        SXSPath                     = 'F:\Source\sxs'
        
		Role						= "ReplicaServerNode"

        DisksPresent                = $null
		
		StoragePools                = @{ FriendlyName = 'DATA'   ; LUNS = (0,1,2,3,4,5) ; DriveLetter = 'F'; ColumnCount = 2},
                                      @{ FriendlyName = 'LOGS'   ; LUNS = (8)     ; DriveLetter = 'G'},
		                              @{ FriendlyName = 'TEMPDB'   ; LUNS = (12) ; DriveLetter = 'H'},
									  @{ FriendlyName = 'BACKUP'   ; LUNS = (15) ; DriveLetter = 'I'}	
		

		WindowsFeatureSetPresent    = @( "RSAT-Clustering-PowerShell","RSAT-AD-PowerShell","RSAT-Clustering-Mgmt",
                                         "Failover-Clustering","NET-Framework-Core","RSAT-AD-AdminCenter" )
		
		# no Internet access by default with Standard load balancer
 		 PowerShellModulesPresent    = @{Name = 'NTFSSecurity'; RequiredVersion = '4.2.3'},
										@{Name = 'SQLServer'; RequiredVersion = '21.0.17199'}
 
        UserRightsAssignmentPresent = @{identity = "NT SERVICE\MSSQL`${0}"
                                        policy = 'Perform_volume_maintenance_tasks'},

                                     @{identity = "NT SERVICE\MSSQL`${0}"
                                        policy = 'Lock_pages_in_memory'}

		SQLServerLogins             = @{Name = 'NT SERVICE\ClusSvc'},
		                              @{Name = 'NT AUTHORITY\SYSTEM'} 


       	SQLServerPermissions 		= @{Name = 'NT SERVICE\ClusSvc' 
                                        Permission = 'AlterAnyAvailabilityGroup','ViewServerState','ConnectSql'},

										@{Name = 'NT AUTHORITY\SYSTEM' 
                                        Permission = 'AlterAnyAvailabilityGroup','ViewServerState','ConnectSql'} 
       
		DirectoryPresent            = 'F:\Source'

		DirectoryPresentSource2      = @{filesSourcePath      = '\\{0}.file.core.windows.net\source\OMSDependencyAgent\'
									    filesDestinationPath = 'F:\Source\OMSDependencyAgent\'},

                                      @{filesSourcePath      = '\\{0}.file.core.windows.net\source\SQL2016\'
									    filesDestinationPath = 'F:\Source\SQL2016\'},
        
                                      @{filesSourcePath      = '\\{0}.file.core.windows.net\source\SXS\'
									    filesDestinationPath = 'F:\Source\SXS\'}
        
        

		SoftwarePackagePresent2      = @{Name            = 'Microsoft Monitoring Agent'
			                            Path            = 'F:\Source\OMSDependencyAgent\InstallDependencyAgent-Windows.exe'
			                            ProductId       = ''
                                        Arguments       = '/S'},

                                      @{Name            = 'Microsoft SQL Server Management Studio - 17.5'
			                            Path            = 'F:\Source\SQL2016\SSMS-Setup-ENU.exe'
			                            ProductId       = ''
                                        Arguments       = '/install /quiet /norestart'}
      
		RegistryKeyPresent          = @{ Key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; 
                                         ValueName = 'DontUsePowerShellOnWinX';	ValueData = 0 ; ValueType = 'Dword'},

                                      @{ Key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; 
                                         ValueName = 'TaskbarGlomLevel';	ValueData = 1 ; ValueType = 'Dword'}
		                                     
     },
    @{ 
        NodeName	= "Localhost" 
	}
 )
}
