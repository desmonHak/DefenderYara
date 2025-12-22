
rule VirTool_Win32_SuspClickFix_M{
	meta:
		description = "VirTool:Win32/SuspClickFix.M,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 } //5 http
		$a_00_1 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_2 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 } //1 msiexec
		$a_00_3 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=6
 
}
rule VirTool_Win32_SuspClickFix_M_2{
	meta:
		description = "VirTool:Win32/SuspClickFix.M,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 66 00 69 00 6e 00 67 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {72 00 6f 00 6f 00 74 00 40 00 66 00 69 00 6e 00 67 00 65 00 72 00 2e 00 } //1 root@finger.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}