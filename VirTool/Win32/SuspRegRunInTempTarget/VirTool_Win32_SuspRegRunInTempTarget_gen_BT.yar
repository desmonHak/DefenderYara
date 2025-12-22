
rule VirTool_Win32_SuspRegRunInTempTarget_gen_BT{
	meta:
		description = "VirTool:Win32/SuspRegRunInTempTarget.gen!BT,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {72 00 65 00 67 00 2e 00 65 00 78 00 65 00 } //1 reg.exe
		$a_00_1 = {20 00 61 00 64 00 64 00 20 00 } //1  add 
		$a_00_2 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 } //1 \AppData\Local\Temp\
		$a_00_3 = {5c 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 \Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_4 = {20 00 2f 00 76 00 20 00 } //1  /v 
		$a_00_5 = {20 00 2f 00 64 00 20 00 } //1  /d 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}