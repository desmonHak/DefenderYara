
rule Trojan_Win64_Amadey_PGAS_MTB{
	meta:
		description = "Trojan:Win64/Amadey.PGAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8f e8 1f a8 68 7d bf f9 bb 6b e9 6a 3b ee c1 7a 63 c1 9f ef c7 03 ea f2 43 89 69 4a e0 7e 5e 0a 5f 7f e8 75 35 ea 52 13 f4 67 2f 28 04 99 06 c6 c9 5e 6d bc 18 a5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}