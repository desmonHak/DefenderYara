
rule HackTool_MacOS_SuspRevShellPayload_A1{
	meta:
		description = "HackTool:MacOS/SuspRevShellPayload.A1,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {40 00 80 d2 21 00 80 d2 02 00 80 d2 10 40 a0 d2 30 0c 80 f2 } //1
		$a_00_1 = {01 00 00 d4 } //1
		$a_00_2 = {10 40 a0 d2 50 0c 80 f2 } //1
		$a_00_3 = {10 40 a0 d2 50 0b 80 f2 } //1
		$a_00_4 = {10 40 a0 d2 70 07 80 f2 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}