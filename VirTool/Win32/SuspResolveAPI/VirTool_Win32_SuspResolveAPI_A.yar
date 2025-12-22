
rule VirTool_Win32_SuspResolveAPI_A{
	meta:
		description = "VirTool:Win32/SuspResolveAPI.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 cf 20 20 20 20 81 ff 6e 74 64 6c 75 ?? 8b 7a 04 81 cf 20 20 20 20 81 ff 6c 2e 64 6c 75 ?? 66 8b 52 08 66 83 ca 20 66 83 fa 6c 75 } //1
		$a_01_1 = {ba 4b 69 00 00 66 3b c2 75 } //1
		$a_01_2 = {ba 52 74 00 00 66 3b c2 75 } //1
		$a_01_3 = {b8 5a 77 00 00 66 39 01 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}