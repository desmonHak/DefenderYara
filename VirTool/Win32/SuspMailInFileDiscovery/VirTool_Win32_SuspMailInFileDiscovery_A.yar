
rule VirTool_Win32_SuspMailInFileDiscovery_A{
	meta:
		description = "VirTool:Win32/SuspMailInFileDiscovery.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //1 cmd
		$a_00_1 = {2f 00 63 00 20 00 64 00 69 00 72 00 20 00 2f 00 62 00 20 00 2f 00 73 00 20 00 2e 00 6f 00 73 00 74 00 } //1 /c dir /b /s .ost
		$a_00_2 = {7c 00 20 00 66 00 69 00 6e 00 64 00 73 00 74 00 72 00 20 00 2f 00 65 00 20 00 2e 00 6f 00 73 00 74 00 } //1 | findstr /e .ost
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}