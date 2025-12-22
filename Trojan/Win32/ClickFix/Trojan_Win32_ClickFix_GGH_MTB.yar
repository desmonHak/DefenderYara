
rule Trojan_Win32_ClickFix_GGH_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGH!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,66 00 66 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 50 00 4f 00 53 00 54 00 3b 00 20 00 69 00 65 00 78 00 20 00 24 00 } //100 Method POST; iex $
		$a_00_1 = {2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 .Content
		$a_02_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=102
 
}