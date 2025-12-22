
rule Trojan_Win64_Tedy_KAE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8d 50 bf 44 8d 48 20 41 80 fa 1a 45 8d 50 bf 41 0f 42 c1 45 8d 48 20 66 41 83 fa 1a 45 0f 42 c1 44 38 c0 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}