
rule VirTool_Win32_DumpLsassProc_SB{
	meta:
		description = "VirTool:Win32/DumpLsassProc.SB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1 rundll32.exe
		$a_02_1 = {5c 00 63 00 6f 00 6d 00 73 00 76 00 63 00 73 00 2e 00 64 00 6c 00 6c 00 [0-ff] 32 00 34 00 20 00 90 29 05 00 20 00 [0-ff] 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 74 00 65 00 6d 00 70 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}