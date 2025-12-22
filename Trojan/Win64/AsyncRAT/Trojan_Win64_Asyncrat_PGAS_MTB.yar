
rule Trojan_Win64_Asyncrat_PGAS_MTB{
	meta:
		description = "Trojan:Win64/Asyncrat.PGAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 03 c8 0f b6 c1 0f b6 4c 05 10 30 0c 1f 48 8d 4d 10 41 0f b6 c2 4c 03 c0 41 0f b6 10 45 8d 1c 11 41 0f b6 c3 48 03 c8 0f b6 01 41 88 00 88 11 41 0f b6 08 48 03 ca 0f b6 c1 0f b6 4c 05 10 30 4c 1f 01 48 83 c3 02 48 81 fb ?? ?? ?? ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}