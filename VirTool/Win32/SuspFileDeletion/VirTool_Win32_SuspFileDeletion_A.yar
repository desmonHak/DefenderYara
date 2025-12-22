
rule VirTool_Win32_SuspFileDeletion_A{
	meta:
		description = "VirTool:Win32/SuspFileDeletion.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 cmd.exe
		$a_00_1 = {20 00 2f 00 63 00 20 00 64 00 65 00 6c 00 20 00 2f 00 71 00 20 00 } //1  /c del /q 
		$a_00_2 = {20 00 63 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 } //1  c:\Windows\
		$a_00_3 = {70 00 69 00 63 00 75 00 73 00 5f 00 72 00 65 00 77 00 69 00 6e 00 64 00 } //-100 picus_rewind
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-100) >=3
 
}