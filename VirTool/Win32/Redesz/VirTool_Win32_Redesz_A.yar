
rule VirTool_Win32_Redesz_A{
	meta:
		description = "VirTool:Win32/Redesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 18 c7 44 24 14 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 0c 01 00 00 00 c7 44 24 08 00 04 00 00 ?? ?? ?? ?? ?? ?? 89 44 24 04 8b 45 f0 89 04 24 ?? ?? ?? ?? ?? 83 ec ?? 89 45 ec 83 7d ec 00 } //1
		$a_03_1 = {c7 44 24 04 01 00 00 00 c7 04 24 ?? 00 00 00 ?? ?? ?? ?? ?? 83 ec 08 89 45 e8 81 7d e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}