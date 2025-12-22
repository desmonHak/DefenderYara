
rule Trojan_Win32_ClickFix_HHW_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HHW!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {2d 00 6d 00 65 00 74 00 68 00 6f 00 64 00 20 00 70 00 6f 00 73 00 74 00 3b 00 69 00 65 00 78 00 20 00 24 00 [0-10] 2e 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1
		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}