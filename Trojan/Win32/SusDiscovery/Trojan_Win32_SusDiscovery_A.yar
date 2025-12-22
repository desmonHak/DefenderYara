
rule Trojan_Win32_SusDiscovery_A{
	meta:
		description = "Trojan:Win32/SusDiscovery.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 6d 69 63 2e 65 78 65 } //wmic.exe  1
		$a_80_1 = {63 73 70 72 6f 64 75 63 74 } //csproduct  1
		$a_80_2 = {67 65 74 20 55 55 49 44 } //get UUID  1
		$a_00_3 = {69 00 66 00 39 00 30 00 34 00 34 00 62 00 32 00 2d 00 63 00 32 00 61 00 62 00 2d 00 34 00 62 00 34 00 33 00 2d 00 39 00 31 00 64 00 35 00 2d 00 62 00 62 00 35 00 61 00 65 00 64 00 64 00 63 00 34 00 64 00 37 00 36 00 } //-1 if9044b2-c2ab-4b43-91d5-bb5aeddc4d76
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}