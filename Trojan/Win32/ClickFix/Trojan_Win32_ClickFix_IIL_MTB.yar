
rule Trojan_Win32_ClickFix_IIL_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.IIL!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {7c 00 20 00 63 00 6d 00 64 00 } //1 | cmd
		$a_02_1 = {63 00 6d 00 64 00 [0-50] 20 00 2f 00 63 00 20 00 } //1
		$a_00_2 = {2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 } //1 --headless
		$a_00_3 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 } //1 conhost
		$a_02_4 = {66 00 69 00 6e 00 67 00 65 00 72 00 [0-50] 40 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}