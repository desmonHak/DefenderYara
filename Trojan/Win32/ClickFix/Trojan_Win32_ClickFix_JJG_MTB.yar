
rule Trojan_Win32_ClickFix_JJG_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.JJG!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 00 74 00 61 00 72 00 74 00 20 00 6d 00 73 00 68 00 74 00 61 00 20 00 68 00 74 00 74 00 70 00 } //1 start mshta http
		$a_00_1 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 69 00 6d 00 } //1 taskkill /im
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}