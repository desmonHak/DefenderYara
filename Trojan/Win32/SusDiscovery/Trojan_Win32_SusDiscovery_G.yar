
rule Trojan_Win32_SusDiscovery_G{
	meta:
		description = "Trojan:Win32/SusDiscovery.G,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 43 72 65 61 74 65 20 2f 46 20 2f 58 4d 4c } //schtasks.exe /Create /F /XML  1
		$a_80_1 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_2 = {57 69 6e 69 6e 65 74 2e 78 6d 6c } //Wininet.xml  1
		$a_00_3 = {2f 00 74 00 6e 00 } //1 /tn
		$a_80_4 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 4d 61 69 6e 74 65 6e 61 6e 63 65 5c 57 69 6e 69 6e 65 74 } //Microsoft\Windows\Maintenance\Wininet  1
		$a_00_5 = {34 00 62 00 37 00 39 00 66 00 66 00 61 00 62 00 2d 00 61 00 32 00 32 00 30 00 2d 00 34 00 65 00 64 00 35 00 2d 00 61 00 36 00 33 00 64 00 2d 00 31 00 66 00 31 00 61 00 39 00 30 00 34 00 35 00 31 00 31 00 33 00 64 00 } //-1 4b79ffab-a220-4ed5-a63d-1f1a9045113d
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*-1) >=5
 
}