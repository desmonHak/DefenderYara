
rule Trojan_BAT_Jalapeno_LM_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 74 1e 00 00 01 6f a2 00 00 0a 28 a3 00 00 0a 39 11 00 00 00 02 74 1e 00 00 01 6f a2 00 00 0a 0a dd d3 00 00 00 dd 06 00 00 00 26 dd 00 00 00 00 00 02 74 1e 00 00 01 6f 92 00 00 0a 6f a4 00 00 0a 6f a5 00 00 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}