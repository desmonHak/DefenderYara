
rule Trojan_Win64_NitrogenLdr_PCO_MTB{
	meta:
		description = "Trojan:Win64/NitrogenLdr.PCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 94 c0 31 d2 0f b6 c0 ?? ?? ?? ?? ?? ?? ?? 8a 04 0f 88 04 0b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}