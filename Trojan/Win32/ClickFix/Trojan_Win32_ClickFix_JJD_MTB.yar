
rule Trojan_Win32_ClickFix_JJD_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.JJD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {29 00 2e 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 7c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 ).Content|powershell
		$a_00_1 = {3b 00 65 00 63 00 68 00 6f 00 28 00 } //1 ;echo(
		$a_02_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}