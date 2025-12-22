
rule Trojan_Win64_Oyster_ZB_MTB{
	meta:
		description = "Trojan:Win64/Oyster.ZB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 53 50 48 85 d2 74 30 66 83 7b 48 00 76 29 41 b8 40 00 00 00 48 8d 4c 24 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}