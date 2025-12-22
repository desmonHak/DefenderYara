
rule Trojan_Win32_SusRegistryModification_D{
	meta:
		description = "Trojan:Win32/SusRegistryModification.D,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } //reg.exe add  1
		$a_80_1 = {48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce  1
		$a_80_2 = {2f 76 20 22 2a 41 73 74 72 61 5a 65 6e 65 63 61 22 } ///v "*AstraZeneca"  1
		$a_80_3 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_00_4 = {20 00 2f 00 64 00 } //1  /d
		$a_00_5 = {20 00 2f 00 66 00 } //1  /f
		$a_80_6 = {64 75 6d 6d 79 2e 65 78 65 } //dummy.exe  1
		$a_00_7 = {39 00 39 00 31 00 61 00 61 00 35 00 38 00 64 00 2d 00 38 00 39 00 31 00 63 00 2d 00 34 00 35 00 64 00 36 00 2d 00 38 00 63 00 63 00 30 00 2d 00 35 00 33 00 65 00 64 00 64 00 33 00 61 00 66 00 37 00 39 00 32 00 61 00 } //-1 991aa58d-891c-45d6-8cc0-53edd3af792a
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_80_6  & 1)*1+(#a_00_7  & 1)*-1) >=7
 
}
rule Trojan_Win32_SusRegistryModification_D_2{
	meta:
		description = "Trojan:Win32/SusRegistryModification.D,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } //reg.exe add  1
		$a_80_1 = {48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4e 65 74 77 69 72 65 } //HKCU\Software\Microsoft\Netwire  1
		$a_00_2 = {20 00 2f 00 46 00 } //1  /F
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}