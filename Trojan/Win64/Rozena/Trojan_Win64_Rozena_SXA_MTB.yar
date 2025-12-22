
rule Trojan_Win64_Rozena_SXA_MTB{
	meta:
		description = "Trojan:Win64/Rozena.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 01 f6 48 01 de 42 0f b7 04 36 48 8d 04 83 42 8b 04 28 48 01 d8 eb 04 } //20
		$a_01_1 = {44 8a 04 01 45 84 c0 74 1d 45 8d 48 e0 41 80 f8 59 7e 04 45 8d 48 fc 66 45 0f be c9 66 44 89 0c 42 48 ff c0 eb da } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}