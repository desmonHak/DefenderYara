
rule VirTool_Win64_Gobesesz_A_MTB{
	meta:
		description = "VirTool:Win64/Gobesesz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 9c 24 00 01 00 00 48 89 bc 24 10 01 00 00 48 83 f9 04 ?? ?? 81 3b [0-10] 44 0f 11 bc 24 b8 00 00 00 48 89 f8 48 89 f3 [0-12] 48 89 8c 24 b8 00 00 00 48 89 84 24 c0 00 00 00 48 8d } //1
		$a_03_1 = {48 8b 94 24 b0 00 00 00 49 89 c1 49 89 d8 48 89 8c 24 b0 00 00 00 4c 89 84 24 a8 00 00 00 4c 89 8c 24 38 01 00 00 [0-11] b9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}