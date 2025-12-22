
rule Trojan_Win64_StealC_SG_MTB{
	meta:
		description = "Trojan:Win64/StealC.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 0f b6 94 04 ?? ?? ?? ?? 45 0f b6 1c 09 41 01 c3 45 31 d3 46 88 9c 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}