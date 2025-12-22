
rule Trojan_Win32_SusBootLogonAutostart_G{
	meta:
		description = "Trojan:Win32/SusBootLogonAutostart.G,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } //reg.exe add  1
		$a_80_1 = {48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_2 = {2f 74 20 52 45 47 5f 53 5a 20 2f 46 20 2f 44 } ///t REG_SZ /F /D  1
		$a_80_3 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_00_4 = {2e 00 74 00 78 00 74 00 } //1 .txt
		$a_00_5 = {20 00 2f 00 56 00 } //1  /V
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}