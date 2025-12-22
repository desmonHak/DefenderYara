
rule Trojan_Win64_ValleyRAT_CBK_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.CBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 d1 d3 e8 89 c1 48 8b 44 24 ?? 33 08 89 08 48 8b 44 24 ?? 48 83 c0 01 48 89 44 24 } //2
		$a_03_1 = {d3 e0 89 c0 48 31 c2 48 8b 44 24 ?? 8b 08 48 01 d1 89 08 48 8b 44 24 ?? 48 83 c0 ?? 48 89 44 24 ?? e9 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}