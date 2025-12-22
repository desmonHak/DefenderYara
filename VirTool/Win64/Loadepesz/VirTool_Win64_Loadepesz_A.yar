
rule VirTool_Win64_Loadepesz_A{
	meta:
		description = "VirTool:Win64/Loadepesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 85 d8 1c 00 00 [0-20] 48 89 45 08 ?? ?? ?? ?? ?? ?? ?? 48 89 45 28 c7 44 24 20 00 00 00 00 45 33 c9 45 33 c0 ba 01 00 00 00 48 8b 4d 08 } //1
		$a_01_1 = {48 8b 85 38 14 00 00 48 8b 00 48 8b 8d 48 11 00 00 48 03 c8 48 8b c1 48 89 85 d8 14 00 00 48 8b 85 d8 14 00 00 48 83 c0 02 48 89 85 b8 1c 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}