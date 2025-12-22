
rule VirTool_Win64_AccessMe_B{
	meta:
		description = "VirTool:Win64/AccessMe.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 41 01 4d 63 d9 ?? ?? ?? ?? 41 0f b6 1c 02 0f b6 41 02 41 0f b6 14 02 0f b6 41 03 41 89 dc 41 c0 ec 04 41 0f b6 3c 02 0f b6 01 41 0f b6 04 02 c1 e0 02 44 09 e0 43 88 04 18 80 fa } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}