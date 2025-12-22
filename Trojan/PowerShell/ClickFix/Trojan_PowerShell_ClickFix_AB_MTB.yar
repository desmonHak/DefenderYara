
rule Trojan_PowerShell_ClickFix_AB_MTB{
	meta:
		description = "Trojan:PowerShell/ClickFix.AB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 } //1 invoke-webrequest
		$a_00_1 = {69 00 77 00 72 00 } //1 iwr
		$a_00_2 = {2d 00 75 00 73 00 65 00 62 00 } //1 -useb
		$a_00_3 = {2e 00 63 00 6f 00 6d 00 2f 00 72 00 75 00 6e 00 2f 00 } //10 .com/run/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*10) >=12
 
}