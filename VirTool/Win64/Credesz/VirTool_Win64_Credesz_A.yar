
rule VirTool_Win64_Credesz_A{
	meta:
		description = "VirTool:Win64/Credesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b c3 49 8b d6 e8 [0-11] 48 39 44 24 60 [0-10] c7 44 24 68 01 00 00 00 41 b9 04 00 00 00 48 89 44 24 20 ?? ?? ?? ?? ?? 48 8b d6 48 8b cf ff } //1
		$a_03_1 = {33 db 41 b9 04 00 00 00 89 5d ?? ?? ?? ?? ?? 48 89 44 24 20 49 8b d6 48 8b cf ff ?? ?? ?? ?? ?? 85 c0 ?? ?? 83 7d a0 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}