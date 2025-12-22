
rule VirTool_Win64_Fredesz_B_MTB{
	meta:
		description = "VirTool:Win64/Fredesz.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b f8 33 c0 b9 18 00 00 00 f3 aa c7 45 08 18 00 00 00 c7 45 18 01 00 00 00 48 c7 45 10 00 00 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 80 00 00 00 c7 44 24 20 02 00 00 00 ?? ?? ?? ?? 45 33 c0 ba 00 00 00 40 48 8d } //1
		$a_03_1 = {8b 95 a8 05 00 00 48 8b c8 [0-13] 48 8b c8 ?? ?? ?? ?? ?? 48 8b 95 70 05 00 00 48 8b c8 [0-12] 48 8b c8 ?? ?? ?? ?? ?? 48 8b 95 60 05 00 00 48 8b c8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}