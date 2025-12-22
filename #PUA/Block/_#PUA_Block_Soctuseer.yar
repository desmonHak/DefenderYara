
rule _#PUA_Block_Soctuseer{
	meta:
		description = "!#PUA:Block:Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 61 6a 61 6d 5f 36 34 2e 70 64 62 } //wajam_64.pdb  2
		$a_80_1 = {65 78 63 65 70 74 69 6f 6e 5f 70 74 72 2e 68 70 70 } //exception_ptr.hpp  1
		$a_80_2 = {73 74 72 69 6e 67 5f 70 61 74 68 2e 68 70 70 } //string_path.hpp  1
		$a_80_3 = {57 61 6a 61 6d 20 57 65 62 20 45 6e 68 61 6e 63 65 72 20 4d 6f 6e 69 74 6f 72 } //Wajam Web Enhancer Monitor  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_Soctuseer_2{
	meta:
		description = "!#PUA:Block:Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {57 61 6a 61 6d } //Wajam  2
		$a_80_1 = {63 69 75 76 6f 2e 63 6f 6d } //ciuvo.com  1
		$a_80_2 = {69 74 2e 74 75 74 6f 34 70 63 2e 63 6f 6d } //it.tuto4pc.com  1
		$a_80_3 = {33 33 37 2e 65 6c 65 78 69 6d 67 2e 63 6f 6d } //337.eleximg.com  1
		$a_80_4 = {70 72 6f 66 69 6c 65 73 2e 69 6e 69 } //profiles.ini  1
		$a_80_5 = {66 72 65 65 20 6f 66 66 65 72 73 20 61 6e 64 20 64 69 73 63 6f 75 6e 74 73 } //free offers and discounts  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule _#PUA_Block_Soctuseer_3{
	meta:
		description = "!#PUA:Block:Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 52 65 6c 65 61 73 65 5c 57 61 6a 61 6d 49 6e 74 65 72 6e 65 74 45 6e 68 61 6e 63 65 72 2e 70 64 62 } //1 \Release\WajamInternetEnhancer.pdb
		$a_00_1 = {57 61 6a 61 6d 49 6e 74 65 72 6e 65 74 45 6e 68 61 6e 63 65 72 2e 65 78 65 } //1 WajamInternetEnhancer.exe
		$a_80_2 = {57 61 6a 61 6d 2e 50 72 6f 78 79 2e 41 74 74 61 63 68 } //Wajam.Proxy.Attach  1
		$a_80_3 = {57 4a 50 72 6f 78 79 2e 46 69 64 64 6c 65 72 43 6f 72 65 2e 64 6c 6c } //WJProxy.FiddlerCore.dll  1
		$a_80_4 = {57 61 6a 61 6d 4d 75 74 65 78 74 } //WajamMutext  1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Soctuseer_4{
	meta:
		description = "!#PUA:Block:Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {64 6f 77 6e 6c 6f 61 64 66 61 6c 6c 62 61 63 6b 2e 77 61 6a 61 6d 2e 63 6f 6d } //downloadfallback.wajam.com  1
		$a_80_1 = {53 4f 46 54 57 41 52 45 5c 57 61 6a 61 6d 5c 55 70 64 61 74 65 } //SOFTWARE\Wajam\Update  1
		$a_02_2 = {55 00 70 00 64 00 61 00 74 00 65 00 72 00 5c 00 [0-0f] 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-1f] 2e 00 70 00 64 00 62 00 } //1
		$a_02_3 = {55 70 64 61 74 65 72 5c [0-0f] 5c 52 65 6c 65 61 73 65 5c [0-1f] 2e 70 64 62 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}
rule _#PUA_Block_Soctuseer_5{
	meta:
		description = "!#PUA:Block:Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {57 61 6a 61 6d 49 6e 74 65 72 6e 65 74 45 6e 68 61 6e 63 65 72 2e 65 78 65 } //WajamInternetEnhancer.exe  1
		$a_80_1 = {57 41 4a 41 4d 5f 52 45 47 5f 4b 45 59 } //WAJAM_REG_KEY  1
		$a_80_2 = {46 61 6b 65 54 75 6e 6e 65 6c } //FakeTunnel  1
		$a_80_3 = {6e 6f 20 64 65 63 72 79 70 74 69 6f 6e 20 66 6f 72 20 79 6f 75 20 3a 29 } //no decryption for you :)  1
		$a_80_4 = {47 6c 6f 62 61 6c 5c 57 61 6a 61 6d 2e 50 72 6f 78 79 2e 41 62 6e 6f 72 6d 61 6c 54 65 72 6d 69 6e 61 74 69 6f 6e } //Global\Wajam.Proxy.AbnormalTermination  1
		$a_80_5 = {57 61 6a 61 6d 4d 75 74 65 78 74 } //WajamMutext  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=5
 
}
rule _#PUA_Block_Soctuseer_6{
	meta:
		description = "!#PUA:Block:Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_80_0 = {77 77 77 2e 77 61 6a 61 6d 2e 63 6f 6d } //www.wajam.com  1
		$a_80_1 = {57 61 6a 61 6d 49 6e 74 65 72 6e 65 74 45 6e 68 61 6e 63 65 72 53 65 72 76 69 63 65 2e 70 64 62 } //WajamInternetEnhancerService.pdb  1
		$a_80_2 = {73 6f 66 74 77 61 72 65 5c 57 61 6a 61 6d 5c 57 61 6a 61 6d 20 49 6e 74 65 72 6e 65 74 20 45 6e 68 61 6e 63 65 72 } //software\Wajam\Wajam Internet Enhancer  1
		$a_80_3 = {57 4a 50 72 6f 78 79 54 6f 6f 6c 73 2e 65 78 65 } //WJProxyTools.exe  1
		$a_80_4 = {47 6c 6f 62 61 6c 5c 57 61 6a 61 6d 2e 50 72 6f 78 79 2e 45 76 65 6e 74 } //Global\Wajam.Proxy.Event  1
		$a_80_5 = {57 4a 4d 61 6e 69 66 65 73 74 } //WJManifest  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=4
 
}
rule _#PUA_Block_Soctuseer_7{
	meta:
		description = "!#PUA:Block:Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 61 6a 61 6d 2e 63 6f 6d 2f 77 65 62 65 6e 68 61 6e 63 65 72 2f 6c 6f 67 67 69 6e 67 } //2 http://www.wajam.com/webenhancer/logging
		$a_00_1 = {6e 65 74 77 6f 72 6b 2e 68 74 74 70 2e 73 70 64 79 2e 65 6e 61 62 6c 65 64 } //1 network.http.spdy.enabled
		$a_80_2 = {77 61 6a 61 6d 2e 70 64 62 } //wajam.pdb  2
		$a_80_3 = {57 61 6a 61 6d 20 57 65 62 20 45 6e 68 61 6e 63 65 72 } //Wajam Web Enhancer  2
		$a_80_4 = {52 69 6a 6e 64 61 65 6c 2d 32 35 36 } //Rijndael-256  1
		$a_80_5 = {57 6e 55 6e 69 6e 73 74 2e 65 78 65 } //WnUninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=4
 
}
rule _#PUA_Block_Soctuseer_8{
	meta:
		description = "!#PUA:Block:Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {49 45 5f 42 48 4f 5c 73 6f 75 72 63 65 5c 77 61 6a 61 6d 5c 52 65 6c 65 61 73 65 5c 70 72 69 61 6d 5f 62 68 6f 2e 70 64 62 } //IE_BHO\source\wajam\Release\priam_bho.pdb  1
		$a_80_1 = {77 61 6a 61 6d 2e 57 61 6a 61 6d 42 48 4f 2e 31 20 3d 20 73 20 27 57 61 6a 61 6d 27 } //wajam.WajamBHO.1 = s 'Wajam'  1
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 57 61 6a 61 6d } //Software\Wajam  1
		$a_80_3 = {77 61 6a 61 6d 2e 63 6f 6d 2f 75 70 64 61 74 65 2f 49 6e 74 65 72 6e 65 74 45 78 70 6c 6f 72 65 72 2f 75 70 64 61 74 65 5f 62 68 6f 2e 78 6d 6c } //wajam.com/update/InternetExplorer/update_bho.xml  1
		$a_80_4 = {77 61 6a 61 6d 5f 69 65 5f 61 64 64 6f 6e 5f 69 6e 73 74 61 6c 6c 65 64 3d 31 } //wajam_ie_addon_installed=1  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}
rule _#PUA_Block_Soctuseer_9{
	meta:
		description = "!#PUA:Block:Soctuseer,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_80_0 = {64 3a 5c 50 72 6f 6a 65 63 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 4e 53 49 53 20 50 6c 75 67 69 6e 73 5c 49 70 43 6f 6e 66 69 67 5c 4f 75 74 70 75 74 5c 50 6c 75 67 69 6e 73 5c 49 70 43 6f 6e 66 69 67 2e 70 64 62 } //d:\Projects\Visual Studio\NSIS Plugins\IpConfig\Output\Plugins\IpConfig.pdb  1
		$a_80_1 = {57 61 6a 61 6d 20 57 65 62 20 45 6e 68 61 6e 63 65 72 } //Wajam Web Enhancer  1
		$a_80_2 = {77 61 6a 61 6d 5f 36 34 2e 65 78 65 } //wajam_64.exe  2
		$a_80_3 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_4 = {68 6f 6d 65 64 65 70 6f 74 2e 69 63 6f } //homedepot.ico  1
		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_7 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100+(#a_80_7  & 1)*-100) >=5
 
}
rule _#PUA_Block_Soctuseer_10{
	meta:
		description = "!#PUA:Block:Soctuseer,SIGNATURE_TYPE_PEHSTR,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 63 00 61 00 6c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 } //1 LocalService
		$a_01_1 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 73 00 74 00 6f 00 70 00 70 00 65 00 64 00 } //1 Service stopped
		$a_01_2 = {43 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 6f 00 70 00 65 00 6e 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //1 Could not open Service Manager
		$a_01_3 = {57 00 61 00 6a 00 61 00 49 00 6e 00 74 00 45 00 6e 00 20 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 } //5 WajaIntEn Monitor
		$a_01_4 = {62 72 6f 77 73 65 72 2e 65 6e 61 62 6c 65 64 5f 6c 61 62 73 5f 65 78 70 65 72 69 6d 65 6e 74 73 } //1 browser.enabled_labs_experiments
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1) >=7
 
}