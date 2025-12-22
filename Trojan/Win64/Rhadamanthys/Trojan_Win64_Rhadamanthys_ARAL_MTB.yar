
rule Trojan_Win64_Rhadamanthys_ARAL_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.ARAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 c1 fa 07 48 89 de 48 c1 fb 3f 48 29 da 48 69 d2 68 01 00 00 48 89 f7 48 29 d6 48 89 31 48 c1 eb 3e 48 8d 14 3b 48 89 d3 48 c1 fa 02 48 b8 06 5b b0 05 5b b0 05 5b 48 89 d6 48 f7 ea 48 c1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}