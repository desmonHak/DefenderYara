
rule Trojan_Win32_SuspDiscovery_A{
	meta:
		description = "Trojan:Win32/SuspDiscovery.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 6d 69 63 2e 65 78 65 } //wmic.exe  1
		$a_80_1 = {63 73 70 72 6f 64 75 63 74 } //csproduct  1
		$a_80_2 = {67 65 74 20 55 55 49 44 } //get UUID  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}