
rule VirTool_Win64_Elevatekatz_A{
	meta:
		description = "VirTool:Win64/Elevatekatz.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 18 57 48 81 ec 00 05 00 00 48 8b ?? ?? ?? ?? ?? 48 33 c4 48 89 84 24 f0 04 00 00 48 8b da 48 8b f9 ff } //1
		$a_03_1 = {48 33 c4 48 89 44 24 38 41 b9 01 00 00 00 c6 44 24 30 cc ?? ?? ?? ?? ?? 48 c7 44 24 20 00 00 00 00 48 8b da ff } //1
		$a_03_2 = {4c 89 6c 24 70 49 8b d6 48 89 44 24 20 49 8b cc ?? ?? ?? ?? ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}