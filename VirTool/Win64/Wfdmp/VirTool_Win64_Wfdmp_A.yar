
rule VirTool_Win64_Wfdmp_A{
	meta:
		description = "VirTool:Win64/Wfdmp.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 75 d7 ff ?? ?? ?? ?? ?? 48 8b c8 ?? ?? ?? ?? ba 28 00 00 00 ff } //1
		$a_03_1 = {45 33 c0 ba 00 00 00 40 ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 4c 8b f0 } //1
		$a_03_2 = {48 89 5c 24 30 48 89 5c 24 28 48 c7 44 24 20 04 00 00 00 ?? ?? ?? ?? 33 d2 41 b8 0b 00 02 00 48 8b cf ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}