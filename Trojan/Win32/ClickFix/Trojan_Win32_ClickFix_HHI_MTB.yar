
rule Trojan_Win32_ClickFix_HHI_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HHI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //10
		$a_00_1 = {5b 00 69 00 6e 00 74 00 36 00 34 00 5d 00 28 00 } //10 [int64](
		$a_00_2 = {69 00 72 00 6d 00 20 00 } //1 irm 
		$a_00_3 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 72 00 65 00 73 00 74 00 6d 00 65 00 74 00 68 00 6f 00 64 00 } //1 invoke-restmethod
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=21
 
}