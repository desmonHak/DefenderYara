
rule Trojan_Win32_ClickFix_HHX_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HHX!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 3b 00 69 00 65 00 78 00 28 00 4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 49 00 4f 00 2e 00 53 00 74 00 72 00 65 00 61 00 6d 00 52 00 65 00 61 00 64 00 65 00 72 00 28 00 24 00 } //1 New-Object Net.WebClient;iex(New-Object IO.StreamReader($
		$a_02_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}