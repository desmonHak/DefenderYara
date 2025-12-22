
rule Trojan_Win32_ClickFix_JJB_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.JJB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 69 00 6e 00 67 00 } //1 ping
		$a_00_1 = {3e 00 24 00 6e 00 75 00 6c 00 6c 00 3b 00 69 00 65 00 78 00 28 00 } //1 >$null;iex(
		$a_00_2 = {4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.WebClient
		$a_00_3 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 } //1 DownloadString
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}