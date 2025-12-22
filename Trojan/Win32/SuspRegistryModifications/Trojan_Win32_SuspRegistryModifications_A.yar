
rule Trojan_Win32_SuspRegistryModifications_A{
	meta:
		description = "Trojan:Win32/SuspRegistryModifications.A,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } //reg.exe add  1
		$a_80_1 = {48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce  1
		$a_80_2 = {2f 76 20 22 2a 53 6f 64 69 6e 6f 6b 69 62 69 22 } ///v "*Sodinokibi"  1
		$a_80_3 = {64 75 6d 6d 79 2e 65 78 65 } //dummy.exe  1
		$a_80_4 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_00_5 = {20 00 2f 00 66 00 } //1  /f
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}