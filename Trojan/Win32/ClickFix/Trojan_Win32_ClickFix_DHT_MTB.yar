
rule Trojan_Win32_ClickFix_DHT_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DHT!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,79 00 79 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {2d 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 50 00 6f 00 73 00 74 00 } //10 -Method Post
		$a_00_2 = {29 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //10 ).Content
		$a_00_3 = {68 00 74 00 74 00 70 00 } //1 http
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1) >=121
 
}