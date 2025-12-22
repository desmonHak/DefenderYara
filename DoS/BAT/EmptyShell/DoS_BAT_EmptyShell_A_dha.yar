
rule DoS_BAT_EmptyShell_A_dha{
	meta:
		description = "DoS:BAT/EmptyShell.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 delete shadows /all /quiet
		$a_01_1 = {52 65 67 69 73 74 72 79 43 6c 65 61 6e 65 72 } //1 RegistryCleaner
		$a_01_2 = {57 69 70 65 57 69 74 68 50 72 69 6f 72 69 74 79 } //1 WipeWithPriority
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}