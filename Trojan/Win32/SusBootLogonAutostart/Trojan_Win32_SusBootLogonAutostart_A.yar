
rule Trojan_Win32_SusBootLogonAutostart_A{
	meta:
		description = "Trojan:Win32/SusBootLogonAutostart.A,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 61 64 64 } //reg.exe add  1
		$a_80_1 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4d 69 63 72 6f 73 6f 66 74 } //Applications\Microsoft  1
		$a_80_3 = {2f 74 20 52 45 47 5f 45 58 50 41 4e 44 5f 53 5a 20 2f 76 } ///t REG_EXPAND_SZ /v  1
		$a_80_4 = {77 73 6b 74 72 61 79 2e 65 78 65 } //wsktray.exe  1
		$a_00_5 = {20 00 2f 00 66 00 } //1  /f
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}