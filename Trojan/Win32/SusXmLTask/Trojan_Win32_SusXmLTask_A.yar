
rule Trojan_Win32_SusXmLTask_A{
	meta:
		description = "Trojan:Win32/SusXmLTask.A,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {73 63 68 74 61 73 6b 73 2e 65 78 65 } //schtasks.exe  1
		$a_80_1 = {2f 63 72 65 61 74 65 20 2f 54 4e } ///create /TN  1
		$a_00_2 = {45 00 76 00 65 00 6e 00 74 00 73 00 5c 00 43 00 61 00 63 00 68 00 65 00 54 00 61 00 73 00 6b 00 5f 00 74 00 65 00 73 00 74 00 } //1 Events\CacheTask_test
		$a_80_3 = {2f 58 4d 4c } ///XML  1
		$a_80_4 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_5 = {65 76 65 6e 74 73 2e 78 6d 6c } //events.xml  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}