
rule Ransom_Win64_IndustrialSpy_MKV_MTB{
	meta:
		description = "Ransom:Win64/IndustrialSpy.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_03_0 = {41 c1 e6 08 44 0b f0 8b c6 83 bb a0 00 00 00 00 44 89 75 ec 74 ?? 33 83 ?? 00 00 00 33 83 ?? 00 00 00 89 45 e0 41 8b c6 33 83 ?? 00 00 00 33 83 ?? 00 00 00 eb } //3
		$a_03_1 = {c1 e8 10 88 41 05 8a 45 e4 41 c1 e8 08 44 88 41 06 4c 8b 45 ?? 88 41 07 44 3b ff 0f 82 } //4
		$a_81_2 = {72 65 61 64 6d 65 2e 68 74 6d } //1 readme.htm
		$a_81_3 = {53 65 6c 66 20 64 65 6c 65 74 69 6e 67 } //1 Self deleting
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*4+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=9
 
}