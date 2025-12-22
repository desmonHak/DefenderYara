
rule VirTool_Win32_SuspNetworkDiscovery_A{
	meta:
		description = "VirTool:Win32/SuspNetworkDiscovery.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //1 cmd
		$a_00_1 = {20 00 2f 00 63 00 20 00 } //1  /c 
		$a_00_2 = {6e 00 65 00 74 00 73 00 74 00 61 00 74 00 20 00 2d 00 61 00 } //1 netstat -a
		$a_00_3 = {66 00 69 00 6e 00 64 00 73 00 74 00 72 00 20 00 4c 00 49 00 53 00 54 00 45 00 4e 00 49 00 4e 00 47 00 } //1 findstr LISTENING
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}