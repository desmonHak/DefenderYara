
rule Ransom_Win64_Chaos_PCO_MTB{
	meta:
		description = "Ransom:Win64/Chaos.PCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 48 8d 52 01 40 32 cf ff c0 30 4a ff 3b c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}