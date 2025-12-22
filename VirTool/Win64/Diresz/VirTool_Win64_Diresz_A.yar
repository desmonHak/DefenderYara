
rule VirTool_Win64_Diresz_A{
	meta:
		description = "VirTool:Win64/Diresz.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 c7 44 24 20 ?? ?? 00 00 45 33 c0 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b f8 e8 ?? ?? ?? ?? 8b d8 85 c0 ?? ?? 8b d0 } //1
		$a_03_1 = {4c 8b cf 48 89 74 24 48 45 33 c0 48 89 74 24 40 ba ff ff 1f 00 48 89 74 24 38 48 89 74 24 30 48 89 74 24 28 48 89 44 24 20 e8 ?? ?? ?? ?? 85 c0 } //1
		$a_01_2 = {4c 8b d1 b8 18 00 00 00 0f 05 c3 4c 8b d1 b8 c7 00 00 00 0f 05 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}