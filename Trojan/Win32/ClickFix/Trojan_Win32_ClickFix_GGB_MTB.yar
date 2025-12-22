
rule Trojan_Win32_ClickFix_GGB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {77 00 67 00 65 00 74 00 } //1 wget
		$a_00_2 = {73 00 74 00 61 00 72 00 74 00 20 00 77 00 65 00 62 00 2d 00 69 00 64 00 3a 00 } //1 start web-id:
		$a_00_3 = {2e 00 63 00 6d 00 64 00 } //1 .cmd
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}