
rule Trojan_Win32_ClickFix_DIJ_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DIJ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {72 00 65 00 66 00 73 00 6e 00 61 00 72 00 54 00 73 00 74 00 69 00 42 00 2d 00 74 00 72 00 61 00 74 00 53 00 } //10 refsnarTstiB-tratS
		$a_00_2 = {70 00 74 00 74 00 68 00 } //10 ptth
		$a_00_3 = {50 00 4d 00 45 00 54 00 3a 00 76 00 6e 00 65 00 24 00 } //10 PMET:vne$
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=130
 
}