
rule VirTool_Win32_LsassDump_B{
	meta:
		description = "VirTool:Win32/LsassDump.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {20 00 2f 00 70 00 69 00 64 00 20 00 90 29 03 00 } //1
		$a_02_1 = {20 00 2f 00 66 00 69 00 6c 00 65 00 20 00 90 29 03 00 } //1
		$a_02_2 = {20 00 2f 00 74 00 79 00 70 00 65 00 20 00 90 29 03 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}