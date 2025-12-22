
rule HackTool_Win64_Disabler_AHB_MTB{
	meta:
		description = "HackTool:Win64/Disabler.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b f8 48 89 44 24 38 0f 57 c0 0f 11 00 0f 11 40 ?? 0f b6 03 48 c7 07 } //30
		$a_01_1 = {64 65 66 65 6e 64 65 72 2d 64 69 73 61 62 6c 65 72 2d 69 70 63 } //20 defender-disabler-ipc
		$a_01_2 = {64 65 66 65 6e 64 6e 6f 74 5c 63 78 78 2d 73 68 61 72 65 64 } //10 defendnot\cxx-shared
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}