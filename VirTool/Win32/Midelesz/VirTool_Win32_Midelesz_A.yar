
rule VirTool_Win32_Midelesz_A{
	meta:
		description = "VirTool:Win32/Midelesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 45 f4 83 7d f4 00 [0-22] 83 c4 04 68 e8 03 00 00 ?? ?? ?? ?? ?? ?? 6a 04 68 00 30 00 00 8b 55 f8 52 6a 00 } //1
		$a_03_1 = {8b 4d 0c 8b 14 01 52 [0-10] 83 c4 08 68 e8 03 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 ?? ?? ?? 51 ba 04 00 00 00 c1 e2 00 8b 45 0c 8b 0c 10 51 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}