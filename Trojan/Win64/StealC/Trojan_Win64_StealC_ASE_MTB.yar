
rule Trojan_Win64_StealC_ASE_MTB{
	meta:
		description = "Trojan:Win64/StealC.ASE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 88 04 3a 48 ff c7 66 ?? 48 39 f9 7e ?? 44 0f b7 04 7e 4c 39 c3 76 ?? 46 0f b6 04 00 48 39 f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}