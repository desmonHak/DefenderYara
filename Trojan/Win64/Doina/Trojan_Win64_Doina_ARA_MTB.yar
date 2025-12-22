
rule Trojan_Win64_Doina_ARA_MTB{
	meta:
		description = "Trojan:Win64/Doina.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 09 33 c8 8b c1 48 8b 4c 24 38 48 8b 94 24 60 01 00 00 48 03 d1 48 8b ca 88 01 e9 1a ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}