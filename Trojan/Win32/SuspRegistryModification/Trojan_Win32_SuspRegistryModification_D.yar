
rule Trojan_Win32_SuspRegistryModification_D{
	meta:
		description = "Trojan:Win32/SuspRegistryModification.D,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } //reg.exe add  1
		$a_80_1 = {48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4e 65 74 77 69 72 65 } //HKCU\Software\Microsoft\Netwire  1
		$a_00_2 = {20 00 2f 00 46 00 } //1  /F
		$a_00_3 = {34 00 62 00 37 00 39 00 66 00 66 00 61 00 62 00 2d 00 61 00 32 00 32 00 30 00 2d 00 34 00 65 00 64 00 35 00 2d 00 61 00 36 00 33 00 64 00 2d 00 31 00 66 00 31 00 61 00 39 00 30 00 34 00 35 00 31 00 31 00 33 00 6c 00 } //-1 4b79ffab-a220-4ed5-a63d-1f1a9045113l
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}