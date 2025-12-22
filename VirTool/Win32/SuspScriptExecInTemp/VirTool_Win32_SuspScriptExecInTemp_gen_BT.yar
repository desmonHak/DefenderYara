
rule VirTool_Win32_SuspScriptExecInTemp_gen_BT{
	meta:
		description = "VirTool:Win32/SuspScriptExecInTemp.gen!BT,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 cmd.exe
		$a_00_1 = {20 00 2f 00 63 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 } //1  /c C:\Users\
		$a_00_2 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 } //1 \AppData\Local\Temp\
		$a_00_3 = {2e 00 76 00 62 00 73 00 } //1 .vbs
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}