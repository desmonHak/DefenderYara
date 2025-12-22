
rule Trojan_Win32_Ripinip_PA_MTB{
	meta:
		description = "Trojan:Win32/Ripinip.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8a 14 39 33 d0 8b 44 24 24 03 c2 41 89 44 24 24 8b 44 24 5c 3b c8 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}