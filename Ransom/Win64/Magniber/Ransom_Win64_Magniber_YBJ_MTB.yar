
rule Ransom_Win64_Magniber_YBJ_MTB{
	meta:
		description = "Ransom:Win64/Magniber.YBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 7d f0 90 13 48 89 5d f8 90 13 49 c7 c6 ?? ?? ?? ?? 90 13 49 81 f6 ?? ?? ?? ?? 90 13 41 56 90 13 49 c7 c6 ?? ?? ?? ?? 90 13 49 81 f6 ?? ?? ?? ?? 90 13 41 56 e9 } //1
		$a_03_1 = {48 ff c1 e9 90 0a 05 00 48 ff c1 90 13 48 81 f9 ?? ?? ?? ?? 90 13 90 13 8a a6 ?? ?? ?? ?? 90 13 32 e0 90 13 80 f4 a0 90 13 88 27 90 13 88 27 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}