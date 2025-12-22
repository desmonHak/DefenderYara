
rule Trojan_Win64_Midie_AB_MTB{
	meta:
		description = "Trojan:Win64/Midie.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 20 f2 b3 52 41 20 d8 41 08 d0 44 30 e0 08 c1 40 20 f0 41 20 db 41 08 c3 45 30 c3 40 30 f9 44 08 d9 40 30 f9 44 89 d0 20 c8 44 30 d1 08 c1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}