
rule _#PUA_Block_WeatherAlerts{
	meta:
		description = "!#PUA:Block:WeatherAlerts,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 75 70 65 72 42 61 63 6b 75 70 2e 69 6e 69 } //SuperBackup.ini  1
		$a_80_1 = {53 75 70 65 72 42 61 63 6b 75 70 } //SuperBackup  1
		$a_80_2 = {53 75 70 65 72 42 61 63 6b 75 70 2e 65 78 65 } //SuperBackup.exe  1
		$a_80_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_4 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100) >=3
 
}
rule _#PUA_Block_WeatherAlerts_2{
	meta:
		description = "!#PUA:Block:WeatherAlerts,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_80_0 = {57 65 61 74 68 65 72 41 6c 65 72 74 73 2e 65 78 65 } //WeatherAlerts.exe  1
		$a_80_1 = {57 65 61 74 68 65 72 41 6c 65 72 74 73 } //WeatherAlerts  1
		$a_80_2 = {4c 6f 63 61 6c 20 57 65 61 74 68 65 72 20 4c 4c 43 } //Local Weather LLC  1
		$a_80_3 = {53 65 76 65 72 65 20 57 65 61 74 68 65 72 20 41 6c 65 72 74 } //Severe Weather Alert  1
		$a_80_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100) >=4
 
}
rule _#PUA_Block_WeatherAlerts_3{
	meta:
		description = "!#PUA:Block:WeatherAlerts,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_80_0 = {42 6c 69 74 7a 4d 65 64 69 61 50 6c 61 79 65 72 41 70 70 2e 65 78 65 } //BlitzMediaPlayerApp.exe  1
		$a_80_1 = {42 6c 69 74 7a 4d 65 64 69 61 50 6c 61 79 65 72 41 70 70 2e 50 72 6f 70 65 72 74 69 65 73 } //BlitzMediaPlayerApp.Properties  1
		$a_80_2 = {42 6c 69 74 7a 4d 65 64 69 61 50 6c 61 79 65 72 41 70 70 } //BlitzMediaPlayerApp  1
		$a_80_3 = {42 6c 69 74 7a 4d 65 64 69 61 50 6c 61 79 65 72 41 70 70 2e 52 65 73 6f 75 72 63 65 73 2e 62 74 6e 4d 69 6e 69 6d 69 7a 65 48 6f 76 65 72 2e 62 6d 70 } //BlitzMediaPlayerApp.Resources.btnMinimizeHover.bmp  1
		$a_80_4 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } //Uninstall.exe  -100
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100) >=4
 
}