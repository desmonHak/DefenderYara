
rule Trojan_Win32_SusXmLTask_C{
	meta:
		description = "Trojan:Win32/SusXmLTask.C,SIGNATURE_TYPE_CMDHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 } //schtasks.exe /create  1
		$a_80_1 = {2f 73 63 20 6d 69 6e 75 74 65 20 2f 6d 6f } ///sc minute /mo  1
		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c } //AppData\Local  1
		$a_80_3 = {4d 61 69 6e 74 65 6e 61 6e 63 65 } //Maintenance  1
		$a_00_4 = {2f 00 74 00 6e 00 } //1 /tn
		$a_00_5 = {2e 00 76 00 62 00 73 00 } //1 .vbs
		$a_00_6 = {2f 00 74 00 72 00 } //1 /tr
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}