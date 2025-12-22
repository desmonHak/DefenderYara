
rule Trojan_Win32_ClickFix_DIZ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DIZ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 04 00 00 "
		
	strings :
		$a_00_0 = {26 00 26 00 20 00 63 00 75 00 72 00 6c 00 20 00 2d 00 6b 00 20 00 2d 00 6f 00 20 00 25 00 74 00 65 00 6d 00 70 00 25 00 } //100 && curl -k -o %temp%
		$a_00_1 = {26 00 26 00 20 00 73 00 74 00 61 00 72 00 74 00 } //10 && start
		$a_00_2 = {26 00 26 00 20 00 65 00 63 00 68 00 6f 00 } //10 && echo
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=121
 
}