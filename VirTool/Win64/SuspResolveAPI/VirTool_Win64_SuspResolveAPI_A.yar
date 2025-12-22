
rule VirTool_Win64_SuspResolveAPI_A{
	meta:
		description = "VirTool:Win64/SuspResolveAPI.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {3d 6e 74 64 6c 75 ?? 8b 44 39 04 41 0b c0 3d 6c 2e 64 6c 75 ?? 0f b7 44 39 08 66 83 c8 20 66 83 f8 6c 75 } //1
		$a_01_1 = {b8 52 74 00 00 66 39 06 75 } //1
		$a_01_2 = {b8 4b 69 00 00 66 39 06 75 } //1
		$a_01_3 = {b8 5a 77 00 00 66 39 06 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}