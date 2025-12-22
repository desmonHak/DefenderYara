
rule Trojan_Win32_ClickFix_HHK_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HHK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {47 00 65 00 74 00 2d 00 52 00 61 00 6e 00 64 00 6f 00 6d 00 } //1 Get-Random
		$a_00_1 = {45 00 6e 00 76 00 3a 00 } //1 Env:
		$a_02_2 = {3b 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}