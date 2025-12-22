
rule Trojan_Win32_SusBootLogonAutostart_M{
	meta:
		description = "Trojan:Win32/SusBootLogonAutostart.M,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } //reg.exe add  1
		$a_80_1 = {2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 } ///t REG_DWORD /d  1
		$a_80_2 = {48 4b 43 55 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce  1
		$a_00_3 = {20 00 2f 00 76 00 } //1  /v
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}