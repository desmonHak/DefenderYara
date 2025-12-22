
rule Trojan_Win32_SuspRegistryModification_A{
	meta:
		description = "Trojan:Win32/SuspRegistryModification.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 63 } //powershell.exe -c  1
		$a_80_1 = {55 6e 62 6c 6f 63 6b 2d 46 69 6c 65 } //Unblock-File  1
		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 54 31 31 31 32 2e 70 73 31 } //AppData\Local\Temp\T1112.ps1  1
		$a_00_3 = {34 00 62 00 37 00 39 00 66 00 66 00 61 00 62 00 2d 00 61 00 32 00 32 00 30 00 2d 00 34 00 65 00 64 00 35 00 2d 00 61 00 36 00 33 00 64 00 2d 00 31 00 66 00 31 00 61 00 39 00 30 00 34 00 35 00 31 00 31 00 33 00 69 00 } //-1 4b79ffab-a220-4ed5-a63d-1f1a9045113i
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}