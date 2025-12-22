
rule VirTool_Win32_SuspObfusCmdExec_B{
	meta:
		description = "VirTool:Win32/SuspObfusCmdExec.B,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //1 cmd
		$a_00_1 = {20 00 2f 00 63 00 20 00 } //1  /c 
		$a_00_2 = {3d 00 73 00 74 00 61 00 74 00 26 00 26 00 73 00 65 00 74 00 20 00 } //1 =stat&&set 
		$a_00_3 = {3d 00 6e 00 65 00 74 00 26 00 26 00 63 00 61 00 6c 00 6c 00 20 00 73 00 65 00 74 00 20 00 } //1 =net&&call set 
		$a_00_4 = {26 00 26 00 63 00 61 00 6c 00 6c 00 20 00 25 00 } //1 &&call %
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}