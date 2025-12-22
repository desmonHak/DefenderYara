
rule Trojan_Win32_ClickFix_GGW_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.GGW!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {27 00 2e 00 72 00 65 00 70 00 6c 00 61 00 63 00 65 00 28 00 27 00 } //1 '.replace('
		$a_00_1 = {46 00 55 00 4e 00 43 00 54 00 49 00 4f 00 4e 00 20 00 47 00 4f 00 } //1 FUNCTION GO
		$a_00_2 = {50 00 4f 00 57 00 45 00 52 00 53 00 48 00 45 00 4c 00 4c 00 } //1 POWERSHELL
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}