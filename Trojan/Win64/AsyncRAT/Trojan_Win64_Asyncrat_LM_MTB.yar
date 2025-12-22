
rule Trojan_Win64_Asyncrat_LM_MTB{
	meta:
		description = "Trojan:Win64/Asyncrat.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 48 85 d2 74 2d 83 7a 08 06 75 ?? 48 b8 46 00 6f 00 72 00 6d 00 48 33 42 0c 44 8b 42 14 41 81 f0 61 00 74 00 49 0b c0 75 ?? 48 8b 81 88 00 00 00 eb } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}