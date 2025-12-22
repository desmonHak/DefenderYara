
rule Ransom_Win64_Chaos_CG_MTB{
	meta:
		description = "Ransom:Win64/Chaos.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c2 80 c2 ?? 32 04 0f 32 c1 88 04 0f 48 ff c1 48 81 f9 ?? ?? ?? ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}