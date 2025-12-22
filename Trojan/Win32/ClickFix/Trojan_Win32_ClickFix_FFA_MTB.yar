
rule Trojan_Win32_ClickFix_FFA_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.FFA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {69 00 77 00 72 00 20 00 } //1 iwr 
		$a_02_1 = {68 00 74 00 74 00 70 00 [0-0a] 2e 00 [0-06] 2e 00 [0-06] 2e 00 [0-3c] 2d 00 6d 00 65 00 74 00 68 00 6f 00 64 00 20 00 70 00 6f 00 73 00 74 00 20 00 2d 00 62 00 6f 00 64 00 79 00 20 00 40 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}