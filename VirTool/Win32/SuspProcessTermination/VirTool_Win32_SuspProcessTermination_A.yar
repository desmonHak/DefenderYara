
rule VirTool_Win32_SuspProcessTermination_A{
	meta:
		description = "VirTool:Win32/SuspProcessTermination.A,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {20 00 2d 00 63 00 20 00 } //1  -c 
		$a_00_2 = {67 00 65 00 74 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 } //1 get-process iexplore
		$a_00_3 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2d 00 65 00 78 00 70 00 61 00 6e 00 64 00 20 00 69 00 64 00 3b 00 } //1 select -expand id;
		$a_00_4 = {53 00 74 00 6f 00 70 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 2d 00 49 00 64 00 20 00 24 00 } //1 Stop-Process -Id $
		$a_00_5 = {20 00 2d 00 46 00 6f 00 72 00 63 00 65 00 } //1  -Force
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}