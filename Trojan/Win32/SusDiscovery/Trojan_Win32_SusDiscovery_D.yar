
rule Trojan_Win32_SusDiscovery_D{
	meta:
		description = "Trojan:Win32/SusDiscovery.D,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 53 54 } //schtasks.exe /create /ST  1
		$a_80_1 = {2f 53 43 20 4d 49 4e 55 54 45 20 2f 4d 4f } ///SC MINUTE /MO  1
		$a_80_2 = {73 76 63 68 6f 73 74 2e 65 78 65 } //svchost.exe  1
		$a_80_3 = {2f 54 4e 20 53 74 6f 72 53 79 6e 63 53 76 63 } ///TN StorSyncSvc  1
		$a_00_4 = {34 00 62 00 37 00 39 00 66 00 66 00 61 00 62 00 2d 00 61 00 32 00 32 00 30 00 2d 00 34 00 65 00 64 00 35 00 2d 00 61 00 36 00 33 00 64 00 2d 00 31 00 66 00 31 00 61 00 39 00 30 00 34 00 35 00 31 00 31 00 33 00 63 00 } //-1 4b79ffab-a220-4ed5-a63d-1f1a9045113c
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*-1) >=4
 
}