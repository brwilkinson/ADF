#
# ConfigurationData.psd1
#

@{ 
AllNodes = @( 
    @{ 
        NodeName                    = "LocalHost" 
        PSDscAllowPlainTextPassword = $true
		PSDscAllowDomainUser        = $true

		DisksPresent                = @{DriveLetter="F"; DiskID="2"}
		ServiceSetStopped           = 'ShellHWDetection'

		# IncludesAllSubfeatures
		WindowsFeaturePresent       = 'RSAT'
       
		PowerShellModulesPresent    = 'SQLServer','AzureAD','AzureRM'

		# Single set of features
		WindowsFeatureSetPresent    = 'GPMC',"NET-Framework-Core"
		
		DirectoryPresent            = 'F:\Source'

		                                   
		DirectoryPresentSource       =  @{filesSourcePath = '\\{0}.file.core.windows.net\source\SQLClient\SSMS-Setup-ENU.exe'
										filesDestinationPath = 'F:\Source\SQLClient\SSMS-Setup-ENU.exe'},

                                      @{filesSourcePath      = '\\{0}.file.core.windows.net\source\SXS\'
									    filesDestinationPath = 'F:\Source\SXS\'}

		SoftwarePackagePresent        = @{Name = 'Microsoft SQL Server Management Studio - 17.6'
										Path = 'F:\Source\SQLClient\SSMS-Setup-ENU.exe'
										ProductId = ''
										Arguments = '/install /quiet /norestart'}

		RegistryKeyPresent          = @{ Key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; 
                                         ValueName = 'DontUsePowerShellOnWinX';	ValueData = 0 ; ValueType = 'Dword'},

                                      @{ Key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; 
                                         ValueName = 'TaskbarGlomLevel';	ValueData = 1 ; ValueType = 'Dword'}
     } 
 )
}