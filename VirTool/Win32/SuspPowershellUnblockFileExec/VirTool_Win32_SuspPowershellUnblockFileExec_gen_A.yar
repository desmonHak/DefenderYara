
rule VirTool_Win32_SuspPowershellUnblockFileExec_gen_A{
	meta:
		description = "VirTool:Win32/SuspPowershellUnblockFileExec.gen!A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {20 00 2d 00 63 00 20 00 } //1  -c 
		$a_00_2 = {55 00 6e 00 62 00 6c 00 6f 00 63 00 6b 00 2d 00 46 00 69 00 6c 00 65 00 20 00 } //1 Unblock-File 
		$a_00_3 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 } //1 \AppData\Local\Temp\
		$a_00_4 = {2e 00 70 00 73 00 31 00 27 00 3b 00 20 00 26 00 20 00 } //1 .ps1'; & 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}