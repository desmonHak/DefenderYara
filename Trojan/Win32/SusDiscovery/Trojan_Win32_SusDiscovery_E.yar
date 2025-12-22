
rule Trojan_Win32_SusDiscovery_E{
	meta:
		description = "Trojan:Win32/SusDiscovery.E,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {73 63 2e 65 78 65 20 63 72 65 61 74 65 } //sc.exe create  1
		$a_80_1 = {4d 50 53 45 76 74 4d 61 6e } //MPSEvtMan  1
		$a_80_2 = {62 69 6e 50 61 74 68 3d } //binPath=  1
		$a_80_3 = {57 69 6e 64 6f 77 73 20 46 69 72 65 77 61 6c 6c 20 50 6f 6c 69 63 79 20 45 76 65 6e 74 20 4d 61 6e 61 67 65 72 } //Windows Firewall Policy Event Manager  1
		$a_80_4 = {73 76 63 68 6f 73 74 2e 65 78 65 } //svchost.exe  1
		$a_00_5 = {34 00 62 00 37 00 39 00 66 00 66 00 61 00 62 00 2d 00 61 00 32 00 32 00 30 00 2d 00 34 00 65 00 64 00 35 00 2d 00 61 00 36 00 33 00 64 00 2d 00 31 00 66 00 31 00 61 00 39 00 30 00 34 00 35 00 31 00 31 00 33 00 61 00 } //-1 4b79ffab-a220-4ed5-a63d-1f1a9045113a
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*-1) >=5
 
}