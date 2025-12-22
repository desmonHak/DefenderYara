
rule Trojan_Win64_Zusy_AE_MTB{
	meta:
		description = "Trojan:Win64/Zusy.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 da 30 c2 89 d9 08 c1 80 f1 01 08 d1 80 f1 01 20 d0 20 da 89 c3 80 f3 01 30 d0 80 f2 01 08 da } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}