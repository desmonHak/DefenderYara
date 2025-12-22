
rule Trojan_Win32_SuspRegistryModification_B{
	meta:
		description = "Trojan:Win32/SuspRegistryModification.B,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } //reg.exe add  1
		$a_80_1 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_2 = {2f 74 20 52 45 47 5f 45 58 50 41 4e 44 5f 53 5a } ///t REG_EXPAND_SZ  1
		$a_80_3 = {2f 76 20 50 48 49 4d 45 32 30 31 30 41 53 59 4e 43 20 2f 64 } ///v PHIME2010ASYNC /d  1
		$a_80_4 = {2e 65 78 65 20 2f 66 } //.exe /f  1
		$a_00_5 = {34 00 62 00 37 00 39 00 66 00 66 00 61 00 62 00 2d 00 61 00 32 00 32 00 30 00 2d 00 34 00 65 00 64 00 35 00 2d 00 61 00 36 00 33 00 64 00 2d 00 31 00 66 00 31 00 61 00 39 00 30 00 34 00 35 00 31 00 31 00 33 00 6a 00 } //-1 4b79ffab-a220-4ed5-a63d-1f1a9045113j
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*-1) >=5
 
}