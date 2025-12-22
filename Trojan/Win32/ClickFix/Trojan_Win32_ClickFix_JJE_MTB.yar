
rule Trojan_Win32_ClickFix_JJE_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.JJE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 [0-50] 20 00 2f 00 63 00 } //1
		$a_02_1 = {66 00 69 00 6e 00 67 00 65 00 72 00 [0-50] 40 00 [0-3c] 7c 00 20 00 [0-50] 63 00 6d 00 64 00 } //1
		$a_00_2 = {26 00 20 00 73 00 65 00 74 00 20 00 } //1 & set 
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}