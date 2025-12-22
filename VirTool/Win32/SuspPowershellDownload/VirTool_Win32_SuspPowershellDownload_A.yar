
rule VirTool_Win32_SuspPowershellDownload_A{
	meta:
		description = "VirTool:Win32/SuspPowershellDownload.A,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 powershell.exe
		$a_00_1 = {20 00 2d 00 6e 00 6f 00 70 00 20 00 2d 00 65 00 78 00 65 00 63 00 20 00 62 00 79 00 70 00 61 00 73 00 73 00 20 00 } //1  -nop -exec bypass 
		$a_00_2 = {49 00 45 00 58 00 20 00 28 00 } //1 IEX (
		$a_00_3 = {4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 63 00 6c 00 69 00 65 00 6e 00 74 00 } //1 Net.Webclient
		$a_00_4 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 } //1 .downloadstring(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}