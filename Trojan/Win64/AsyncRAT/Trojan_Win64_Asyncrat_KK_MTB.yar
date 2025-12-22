
rule Trojan_Win64_Asyncrat_KK_MTB{
	meta:
		description = "Trojan:Win64/Asyncrat.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 03 ca 0f b6 c1 0f b6 4c 05 10 42 30 4c 1b 04 41 fe c1 4c 8d 45 10 41 0f b6 c1 48 8d 4d 10 4c 03 c0 41 0f b6 10 44 02 d2 41 0f b6 c2 48 03 c8 0f b6 01 41 88 00 88 11 41 0f b6 08 48 03 ca 0f b6 c1 0f b6 4c 05 10 42 30 4c 1b 05 49 83 c3 06 49 81 fb } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}