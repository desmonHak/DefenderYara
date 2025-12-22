
rule Trojan_Win64_Rozena_AB_MTB{
	meta:
		description = "Trojan:Win64/Rozena.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b9 27 00 00 00 48 89 c7 48 89 d6 f3 48 a5 48 89 f2 48 89 f8 0f b7 0a 66 89 08 48 b8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}