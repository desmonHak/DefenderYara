
rule Trojan_Win64_Rhadamanthys_DA_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 99 c1 ea ?? 01 d0 0f b6 c0 29 d0 4c 63 d8 42 0f b6 54 1c ?? 89 d1 44 01 d2 41 89 d0 41 c1 f8 ?? 41 c1 e8 18 44 01 c2 0f b6 d2 44 29 c2 41 89 d2 48 63 d2 44 0f b6 44 14 ?? 46 88 44 1c ?? 88 4c 14 20 42 02 4c 1c ?? 0f b6 c9 0f b6 54 0c ?? 30 13 48 83 c3 ?? 49 39 d9 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}