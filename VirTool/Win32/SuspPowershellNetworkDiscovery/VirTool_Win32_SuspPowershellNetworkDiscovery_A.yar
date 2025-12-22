
rule VirTool_Win32_SuspPowershellNetworkDiscovery_A{
	meta:
		description = "VirTool:Win32/SuspPowershellNetworkDiscovery.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {20 00 2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00 20 00 68 00 69 00 64 00 64 00 65 00 6e 00 20 00 47 00 65 00 74 00 2d 00 4e 00 65 00 74 00 49 00 50 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 } //1  -window hidden Get-NetIPConfiguration
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}