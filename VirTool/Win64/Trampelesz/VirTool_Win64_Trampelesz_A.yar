
rule VirTool_Win64_Trampelesz_A{
	meta:
		description = "VirTool:Win64/Trampelesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 44 24 28 ?? ?? ?? ?? ?? ?? ?? 33 ff ?? ?? ?? ?? ?? ?? 48 85 c0 [0-19] 48 8b c8 [0-13] 4c 8b c0 48 85 c0 ?? ?? 33 c9 80 38 c3 } //1
		$a_01_1 = {48 8b c1 48 c1 e8 28 88 47 07 48 8b c1 48 c1 e9 38 48 c1 e8 30 88 47 08 88 4f 09 33 c9 66 c7 47 0a 41 ff c6 47 0c e2 c7 44 24 20 00 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}