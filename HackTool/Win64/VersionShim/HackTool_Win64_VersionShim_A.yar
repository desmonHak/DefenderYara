
rule HackTool_Win64_VersionShim_A{
	meta:
		description = "HackTool:Win64/VersionShim.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {56 65 72 73 69 6f 6e 53 68 69 6d } //1 VersionShim
		$a_00_1 = {6c 69 62 72 61 72 69 65 73 2e 74 78 74 } //1 libraries.txt
		$a_01_2 = {51 75 65 75 65 55 73 65 72 41 50 43 } //1 QueueUserAPC
		$a_01_3 = {44 69 73 61 62 6c 65 54 68 72 65 61 64 4c 69 62 72 61 72 79 43 61 6c 6c 73 } //1 DisableThreadLibraryCalls
		$a_01_4 = {80 3b 23 44 8d 69 01 0f 84 98 00 00 00 80 3b 2a 75 5e 85 ed 0f 85 8b 00 00 00 48 8d 4c 24 30 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}