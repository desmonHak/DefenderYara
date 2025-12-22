
rule Trojan_Win32_ClickFix_GGG_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 } //1 mshta http
		$a_00_1 = {2f 00 6d 00 73 00 68 00 74 00 61 00 2e 00 70 00 68 00 70 00 } //1 /mshta.php
		$a_00_2 = {70 00 30 00 6d 00 57 00 56 00 72 00 62 00 6f 00 35 00 58 00 } //1 p0mWVrbo5X
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}