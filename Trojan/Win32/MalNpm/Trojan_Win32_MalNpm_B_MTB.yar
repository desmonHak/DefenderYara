
rule Trojan_Win32_MalNpm_B_MTB{
	meta:
		description = "Trojan:Win32/MalNpm.B!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {77 00 65 00 62 00 68 00 6f 00 6f 00 6b 00 2e 00 73 00 69 00 74 00 65 00 } //1 webhook.site
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}