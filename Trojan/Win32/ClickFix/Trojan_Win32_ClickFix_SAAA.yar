
rule Trojan_Win32_ClickFix_SAAA{
	meta:
		description = "Trojan:Win32/ClickFix.SAAA,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-ff] 90 29 03 00 2e 00 90 29 03 00 2e 00 90 29 03 00 2e 00 90 29 03 00 2f 00 [0-04] 2e 00 6a 00 70 00 67 00 } //11
		$a_02_1 = {50 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-ff] c2 00 a7 00 } //11
	condition:
		((#a_02_0  & 1)*11+(#a_02_1  & 1)*11) >=11
 
}