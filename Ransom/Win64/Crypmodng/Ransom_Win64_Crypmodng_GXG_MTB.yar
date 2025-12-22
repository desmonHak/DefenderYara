
rule Ransom_Win64_Crypmodng_GXG_MTB{
	meta:
		description = "Ransom:Win64/Crypmodng.GXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 f9 41 74 25 8a 94 0c ?? ?? ?? ?? 44 8a 84 0c ?? ?? ?? ?? 41 30 d0 41 20 c0 41 30 d0 44 88 84 0c ?? ?? ?? ?? 48 ff c1 eb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}