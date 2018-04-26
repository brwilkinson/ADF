#
# ConfigurationData.psd1
#

@{ 
AllNodes = @( 
    @{ 
        NodeName = "LocalHost" 
        PSDscAllowPlainTextPassword = $true
		PSDscAllowDomainUser = $true
		
		# IncludesAllSubfeatures
		#WindowsFeaturePresent       = 'RSAT'

		ADUserPresent2               = @{UserName         = "svcAZSQL"
                                        Description      = "Service Account for SQL"},
									  
										@{UserName    = "ProdxGateway"
                                        Description = "Service Account for x"},

										@{UserName    = "ProdxCore"
                                        Description = "Service Account for xCore"},

										@{UserName    = "Prodx"
                                        Description = "Service Account for Prodx"}


		AddDnsRecordPresent2         = @{DnsRecordName    = "Web01"
                                        DNSTargetIP      = "{0}.46"
                                        RecordType       = "ARecord"}


		RegistryKeyPresent          = @{ Key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; 
                                         ValueName = 'DontUsePowerShellOnWinX';	ValueData = 0 ; ValueType = 'Dword'},

                                      @{ Key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; 
                                         ValueName = 'TaskbarGlomLevel';	ValueData = 1 ; ValueType = 'Dword'}
     } 
 )
}
