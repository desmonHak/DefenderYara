
rule Trojan_Win32_SuspSparrow_A{
	meta:
		description = "Trojan:Win32/SuspSparrow.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {72 65 67 2e 65 78 65 20 65 78 70 6f 72 74 20 } //reg.exe export   1
		$a_80_1 = {48 4b 43 55 5c 43 6f 6e 74 72 6f 6c 20 50 61 6e 65 6c 5c 44 65 73 6b 74 6f 70 } //HKCU\Control Panel\Desktop  1
		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_3 = {73 63 72 65 65 6e 73 61 76 65 72 2e 72 65 67 } //screensaver.reg  1
		$a_00_4 = {2f 00 79 00 } //1 /y
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}