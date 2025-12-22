
rule Trojan_Win32_SuspDiscovery_B{
	meta:
		description = "Trojan:Win32/SuspDiscovery.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {6e 74 66 73 69 6e 66 6f 36 34 2e 65 78 65 } //ntfsinfo64.exe  1
		$a_80_1 = {2d 61 63 63 65 70 74 65 75 6c 61 } //-accepteula  1
		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}