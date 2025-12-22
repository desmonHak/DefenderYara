
rule Trojan_Win64_FogFest_A_dha{
	meta:
		description = "Trojan:Win64/FogFest.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_42_0 = {8d 5f 08 eb 90 01 01 48 8b 0b 48 8b d6 e8 90 01 04 85 c0 74 90 01 01 48 83 c3 10 48 83 3b 00 75 90 01 01 48 81 c7 08 10 00 00 48 83 3f 00 eb 90 00 00 } //1
	condition:
		((#a_42_0  & 1)*1) >=1
 
}