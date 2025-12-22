
rule HackTool_Win32_PossibleActiveDirectoryNtdsDumping_A{
	meta:
		description = "HackTool:Win32/PossibleActiveDirectoryNtdsDumping.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6e 00 74 00 64 00 73 00 75 00 74 00 69 00 6c 00 } //1 ntdsutil
		$a_00_1 = {61 00 63 00 74 00 69 00 76 00 61 00 74 00 65 00 20 00 69 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 20 00 6e 00 74 00 64 00 73 00 } //1 activate instance ntds
		$a_00_2 = {63 00 72 00 65 00 61 00 74 00 65 00 20 00 66 00 75 00 6c 00 6c 00 } //1 create full
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}