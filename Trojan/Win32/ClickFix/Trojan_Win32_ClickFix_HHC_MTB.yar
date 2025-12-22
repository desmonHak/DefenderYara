
rule Trojan_Win32_ClickFix_HHC_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.HHC!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2b 00 5b 00 52 00 61 00 6e 00 64 00 6f 00 6d 00 5d 00 3a 00 3a 00 6e 00 65 00 77 00 28 00 29 00 2e 00 4e 00 65 00 78 00 74 00 28 00 } //1 +[Random]::new().Next(
		$a_00_1 = {3b 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 ;powershell
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}