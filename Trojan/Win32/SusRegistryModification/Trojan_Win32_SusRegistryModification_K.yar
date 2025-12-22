
rule Trojan_Win32_SusRegistryModification_K{
	meta:
		description = "Trojan:Win32/SusRegistryModification.K,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } //reg.exe add  1
		$a_80_1 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_2 = {2f 76 20 53 65 63 75 72 69 74 79 48 65 61 6c 74 68 } ///v SecurityHealth  1
		$a_80_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_4 = {2f 74 20 52 45 47 5f 45 58 50 41 4e 44 5f 53 5a } ///t REG_EXPAND_SZ  1
		$a_80_5 = {2f 64 20 74 65 73 74 2e 65 78 65 20 2f 66 } ///d test.exe /f  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}