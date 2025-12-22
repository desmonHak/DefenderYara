
rule VirTool_Win64_Antimalinj_A{
	meta:
		description = "VirTool:Win64/Antimalinj.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 d2 49 8b cf 41 b8 00 08 00 00 ff } //1
		$a_01_1 = {48 89 44 24 38 4c 89 74 24 30 c7 44 24 28 06 00 02 00 44 89 74 24 20 45 33 c9 45 33 c0 48 c7 c1 00 00 00 80 ff } //1
		$a_01_2 = {4c 8b 44 24 58 48 8b 54 24 50 4c 2b c2 b9 01 00 01 00 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}