
rule Trojan_Win64_Dcrat_AMB_MTB{
	meta:
		description = "Trojan:Win64/Dcrat.AMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 83 78 18 0f 4e 8d 14 0a 49 8b c8 76 ?? 49 8b 08 33 d2 49 8b c1 49 f7 70 ?? 49 ff c1 0f b6 04 0a 41 30 02 49 8b 13 49 8b 43 08 48 2b c2 4c 3b c8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}