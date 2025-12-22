
rule VirTool_Win32_EDRBlok_B{
	meta:
		description = "VirTool:Win32/EDRBlok.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {c7 45 f4 00 00 00 00 ?? ?? ?? c7 45 f8 00 00 00 00 bb 01 00 00 00 33 ff 50 6a 08 6a ff ff ?? ?? ?? ?? ?? 85 c0 } //5
		$a_03_1 = {c7 45 f4 00 00 00 00 50 6a 08 6a ff bf 01 00 00 00 c7 45 f8 00 00 00 00 33 db ff ?? ?? ?? ?? ?? 85 c0 } //5
		$a_03_2 = {83 c4 08 8d ?? ?? 50 6a 00 6a 00 6a 19 ff 75 f4 ff } //1
		$a_03_3 = {83 c4 0c ff ?? ff ?? ?? ?? ?? ?? 0f b6 00 48 50 ff ?? ff ?? ?? ?? ?? ?? 8b 30 } //1
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=7
 
}