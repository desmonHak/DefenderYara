
rule Trojan_Win32_Amadey_AYM_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AYM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 83 ec 14 e8 ?? ?? ?? ?? a1 fc 70 41 00 ff d0 c7 44 24 04 ?? ?? ?? ?? 89 04 24 a1 ?? 71 41 00 ff d0 83 ec 08 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}