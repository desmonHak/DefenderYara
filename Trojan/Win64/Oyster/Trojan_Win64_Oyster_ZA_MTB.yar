
rule Trojan_Win64_Oyster_ZA_MTB{
	meta:
		description = "Trojan:Win64/Oyster.ZA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 4c 24 48 c7 44 24 28 40 00 00 00 45 33 c0 48 c7 44 24 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}