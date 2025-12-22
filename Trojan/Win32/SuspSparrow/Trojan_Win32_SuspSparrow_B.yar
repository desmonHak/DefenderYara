
rule Trojan_Win32_SuspSparrow_B{
	meta:
		description = "Trojan:Win32/SuspSparrow.B,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 20 } //reg.exe add   1
		$a_80_1 = {48 4b 43 55 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 } //HKCU\Control Panel\Desktop  1
		$a_80_2 = {2f 74 20 52 45 47 5f 53 5a 20 2f 64 } ///t REG_SZ /d  1
		$a_80_3 = {53 63 72 65 65 6e 53 61 76 65 41 63 74 69 76 65 } //ScreenSaveActive  1
		$a_00_4 = {2f 00 76 00 } //1 /v
		$a_00_5 = {2f 00 66 00 } //1 /f
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}