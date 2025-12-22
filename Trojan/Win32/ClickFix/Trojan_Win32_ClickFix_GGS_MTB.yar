
rule Trojan_Win32_ClickFix_GGS_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGS!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_00_0 = {2d 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 50 00 4f 00 53 00 54 00 3b 00 69 00 65 00 78 00 20 00 24 00 } //10 -Method POST;iex $
		$a_00_1 = {2d 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 50 00 4f 00 53 00 54 00 3b 00 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 65 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 20 00 24 00 } //10 -Method POST;invoke-expression $
		$a_00_2 = {2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 .Content
		$a_00_3 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=12
 
}