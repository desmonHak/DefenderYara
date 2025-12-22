
rule Trojan_Win64_Oyster_ZD_MTB{
	meta:
		description = "Trojan:Win64/Oyster.ZD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 50 45 33 c9 89 44 24 48 45 33 c0 89 44 24 40 33 d2 89 44 24 38 33 c9 89 44 24 30 48 89 44 24 28 89 44 24 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}