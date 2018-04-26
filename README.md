# Azure Deployment Framework [ADF]

Azure Resource Group Deployment - MultiTier Application Environment

	To Deploy all Tiers simply choose the following template
		
		0-azuredeploy-ALL.json
		
	Otherwise start with the template that you need, then proceed onto the next one
	
		1-azuredeploy-OMS.json
		2-azuredeploy-NSG.json
		3-azuredeploy-VNet.json
		4-azuredeploy-ILBalancer.json
		5-azuredeploy-VMApp.json
		6-azuredeploy-WAF.json
		7-azuredeploy-Dashboard.json

	Define the servers you want to deploy using a table in JSON, so you can create as many servers that you need for your application tiers.

	The servers and other services are defined per Environment that you would like to deploy. 
	
	As an example you may have the following Environments:

		azuredeploy.1-dev.parameters.json
		azuredeploy.2-test.parameters.json
		azuredeploy.3-prod.parameters.json
	
	Within these parameter files you define static things within your environment

	An example is below.

``` json
    "Global":{
        "value":{
			"AppName":"MyWebApp",
			"RGName":"AZEU2-MyOrg-rgMyAppGLOBAL",
			"SADiagName":"sanmyappglobaldiageus2",
			"SAName":"samyappglobaleus2",
			"KVName":"AZEU2-MyOrg-kvMyAppGLOBAL",
      "DomainName":"myappdomain.com",
			"AdminUserName":"localadmin",
			"certificateUrl":"https://AZEU2-MyOrg-kvMyAppGLOBAL.vault.azure.net:443/secrets/appwildcard/6854efc0de4584ed4b0346d129fecb74c",
			"certificateThumbprint":"783495FED289452DE730F8F16D52C6BEF636047B",
			"vmStorageAccountType":"Standard_LRS",
			"computeSize":{
				"AD":"Standard_A2m_v2",
				"WEB":"Standard_DS1",
				"CRM":"Standard_DS1",
				"FIL":"Standard_DS1",
				"UTL":"Standard_DS1",
				"PRO":"Standard_DS1"
			}
		}
	}
``` json

There is also a DeploymentInfo object that defines all of the other resources in a deployment

The Domain Controller and DNS Server Settings:

```
	"DeploymentInfo":{
		"value":{
			"DC1PrivateIPAddress":"230",
			"DC2PrivateIPAddress":"231",
			"DC1HostName":"AD01",
			"DC2HostName":"AD02",
```

The Network information including subnets and diffferent address spaces

The following demonstrates 5 SUBNETS of different sizes: 128 + 64 + 32 + 16 + 16 = 256 Host addresses 

This network design fits into a /24 Address Space.

```
	"SubnetInfo":[
		{"name":"MT01","prefix":"0/25"},
		{"name":"FE01","prefix":"128/26"},
		{"name":"BE01","prefix":"192/27"},
		{"name":"AD01","prefix":"224/28"},
		{"name":"WAF01","prefix":"240/28"}
	],
```

The following defines the loadbalaners that are required

``` json
        "LBInfo": [
          {
            "LBName": "PLB01",
            "ASName": "PLB01",
            "Sku": "Standard",
            "PublicIP": "Static",
            "DirectReturn": false,
            "FrontEnd": [
              {
                "Type": "Public",
                "LBFEName": "PLB01"
              }
            ],
            "Services": [
              {
                "LBFEName": "PLB01",
                "RuleName": "WSMAN",
                "LBFEPort": 5985,
                "LBBEPort": 5985,
                "LBBEProbePort": 5985
              }
            ]
          }
	],
```

The following defines the availabilityset and the servers used for SQL

``` json
	"SQLServersAS":[
		{"ASName":"SQL01"}
	],

        "SQLServers": [
          {
            "VMName": "SQL01",
            "ASName": "CLS01",
            "Role": "SQL",
            "Subnet": "BE01",
            "LB": "CLS01",
            "FastNic": 1,
            "Zone": 0,
            "DDRole": "SQL4TB",
            "ClusterInfo": {
              "CLIP": "216",
              "CLNAME": "CLS01",
              "Primary": "SQL01",
              "Secondary": [
                "SQL02"
              ]
            },
            "aoinfo": [
              {
                "GroupName": "AG01",
                "PrimaryAG": "SQL01",
                "SecondaryAG": "SQL02",
                "AOIP": "215",
                "ProbePort": "59999",
                "InstanceName": "ADF_1"
              }
            ]
          },
          {
            "VMName": "SQL02",
            "CLNAME": "CLS01",
            "ASName": "CLS01",
            "Role": "SQL",
            "Subnet": "BE01",
            "LB": "CLS01",
            "FastNic": 1,
            "Zone": 0,
            "Internet": "PLB01",
            "DDRole": "SQL4TB",
            "ClusterInfo": {
              "CLIP": "216",
              "CLNAME": "CLS01",
              "Primary": "SQL01",
              "Secondary": [
                "SQL02"
              ]
            },
            "aoinfo": [
              {
                "GroupName": "AG01",
                "PrimaryAG": "SQL01",
                "SecondaryAG": "SQL02",
                "InstanceName": "ADF_1"
              }
            ]
          }
        ],

```

The following defines the availabilityset and the servers used for SQL

``` json
          "APPServersAS": [
            "JMP"
          ]

          "AppServers": [
            {
              "VMName": "JMP01",
              "Role": "JMP",
              "ASName": "JMP",
              "Subnet": "FE01",
              "DDRole": "127GB",
              "FastNic": 0,
              "PublicIP": "Static",
              "Zone": 0
            }
          ]
```
Close out the DeploymentInfo object

```
		}
	}
}
```
