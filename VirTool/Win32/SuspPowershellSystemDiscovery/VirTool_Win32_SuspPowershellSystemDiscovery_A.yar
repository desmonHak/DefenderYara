
rule VirTool_Win32_SuspPowershellSystemDiscovery_A{
	meta:
		description = "VirTool:Win32/SuspPowershellSystemDiscovery.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 cmd.exe
		$a_00_1 = {20 00 2f 00 63 00 20 00 } //1  /c 
		$a_00_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 20 00 } //1 powershell.exe 
		$a_00_3 = {20 00 47 00 65 00 74 00 2d 00 57 00 6d 00 69 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 2d 00 43 00 6c 00 61 00 73 00 73 00 20 00 77 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 6e 00 } //1  Get-WmiObject -Class win32_ComputerSystemn
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}