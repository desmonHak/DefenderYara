
rule Trojan_Win32_ClickFix_GGI_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGI!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2e 00 70 00 68 00 70 00 20 00 7c 00 20 00 63 00 6d 00 64 00 } //1 .php | cmd
		$a_00_1 = {2f 00 63 00 20 00 63 00 75 00 72 00 6c 00 } //1 /c curl
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}