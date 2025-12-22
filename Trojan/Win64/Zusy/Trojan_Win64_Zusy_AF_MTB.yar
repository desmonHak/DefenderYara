
rule Trojan_Win64_Zusy_AF_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 6d 00 0f 11 84 24 ?? 00 00 00 48 c7 84 24 a0 00 00 00 00 00 00 00 c7 84 24 c0 00 00 00 68 00 00 00 48 c7 04 24 00 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}