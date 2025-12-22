
rule Trojan_Win32_SusBootLogonAutostart_H{
	meta:
		description = "Trojan:Win32/SusBootLogonAutostart.H,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 65 63 68 6f } //cmd.exe /c echo  1
		$a_00_1 = {20 00 3e 00 20 00 } //1  > 
		$a_80_2 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_00_3 = {2e 00 74 00 78 00 74 00 } //1 .txt
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}