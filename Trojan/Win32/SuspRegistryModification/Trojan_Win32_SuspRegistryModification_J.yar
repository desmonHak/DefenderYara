
rule Trojan_Win32_SuspRegistryModification_J{
	meta:
		description = "Trojan:Win32/SuspRegistryModification.J,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } //reg.exe add  1
		$a_80_1 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 } //HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced  1
		$a_80_2 = {2f 76 20 48 69 64 65 46 69 6c 65 45 78 74 } ///v HideFileExt  1
		$a_80_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //rundll32.exe  1
		$a_80_4 = {2f 74 20 52 45 47 5f 44 57 4f 52 44 } ///t REG_DWORD  1
		$a_00_5 = {20 00 2f 00 64 00 } //1  /d
		$a_00_6 = {20 00 2f 00 66 00 } //1  /f
		$a_00_7 = {34 00 62 00 37 00 39 00 66 00 66 00 61 00 62 00 2d 00 61 00 32 00 32 00 30 00 2d 00 34 00 65 00 64 00 35 00 2d 00 61 00 36 00 33 00 64 00 2d 00 31 00 66 00 31 00 61 00 39 00 30 00 34 00 35 00 31 00 31 00 33 00 72 00 } //-1 4b79ffab-a220-4ed5-a63d-1f1a9045113r
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*-1) >=7
 
}