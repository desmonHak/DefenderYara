
rule VirTool_Win32_SuspClickFix_L{
	meta:
		description = "VirTool:Win32/SuspClickFix.L,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {63 00 75 00 72 00 6c 00 [0-08] 20 00 68 00 74 00 74 00 70 00 } //1
		$a_00_1 = {20 00 7c 00 20 00 } //1  | 
		$a_00_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 45 00 78 00 70 00 72 00 65 00 73 00 73 00 69 00 6f 00 6e 00 } //1 Invoke-Expression
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}