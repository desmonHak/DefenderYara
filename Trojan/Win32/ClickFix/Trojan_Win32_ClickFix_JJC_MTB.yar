
rule Trojan_Win32_ClickFix_JJC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.JJC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {28 00 2e 00 28 00 67 00 61 00 6c 00 20 00 2a 00 29 00 5b 00 } //1 (.(gal *)[
		$a_02_1 = {2e 00 6e 00 61 00 6d 00 65 00 29 00 [0-3c] 68 00 74 00 74 00 70 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}