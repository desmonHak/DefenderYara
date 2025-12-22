
rule Trojan_Win32_ClickFix_JJF_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.JJF!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 00 54 00 61 00 72 00 74 00 2d 00 50 00 72 00 4f 00 43 00 45 00 73 00 73 00 20 00 43 00 3a 00 5c 00 } //1 STart-PrOCEss C:\
		$a_00_1 = {77 00 67 00 65 00 74 00 20 00 2d 00 } //1 wget -
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}