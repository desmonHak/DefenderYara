
rule Trojan_Win32_SusXmLTask_B{
	meta:
		description = "Trojan:Win32/SusXmLTask.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 69 72 } //cmd.exe /c dir  1
		$a_80_1 = {6d 6b 64 69 72 } //mkdir  1
		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c } //AppData\Local  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}