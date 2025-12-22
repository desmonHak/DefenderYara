
rule Trojan_Win32_ClickFix_HN_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,19 00 19 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 5e 00 75 00 5e 00 72 00 5e 00 6c 00 20 00 2d 00 73 00 20 00 68 00 5e 00 74 00 5e 00 74 00 5e 00 70 00 } //10 c^u^r^l -s h^t^t^p
		$a_00_1 = {63 00 5e 00 75 00 5e 00 72 00 5e 00 6c 00 20 00 2d 00 73 00 20 00 5e 00 68 00 5e 00 74 00 5e 00 74 00 5e 00 70 00 5e 00 } //10 c^u^r^l -s ^h^t^t^p^
		$a_00_2 = {7c 00 20 00 63 00 6d 00 64 00 20 00 26 00 26 00 20 00 65 00 78 00 69 00 74 00 } //15 | cmd && exit
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*15) >=25
 
}