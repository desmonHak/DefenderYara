
rule VirTool_Win32_SuspNetstatExec_A{
	meta:
		description = "VirTool:Win32/SuspNetstatExec.A,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 cmd.exe
		$a_00_1 = {20 00 2f 00 63 00 20 00 } //1  /c 
		$a_00_2 = {20 00 73 00 65 00 74 00 20 00 } //1  set 
		$a_00_3 = {20 00 2d 00 73 00 20 00 2d 00 70 00 20 00 55 00 44 00 50 00 } //1  -s -p UDP
		$a_00_4 = {3d 00 73 00 74 00 26 00 26 00 } //1 =st&&
		$a_00_5 = {3d 00 6e 00 65 00 74 00 26 00 26 00 } //1 =net&&
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}