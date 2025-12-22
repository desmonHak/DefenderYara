
rule HackTool_MacOS_MythicAgent_X2{
	meta:
		description = "HackTool:MacOS/MythicAgent.X2,SIGNATURE_TYPE_MACHOHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 "
		
	strings :
		$a_01_0 = {65 73 74 50 61 73 73 77 6f 72 64 } //100 estPassword
		$a_01_1 = {75 64 6f 5f 70 6f 73 65 69 64 6f 6e } //100 udo_poseidon
		$a_01_2 = {68 65 6c 6c 63 6f 64 65 5f 74 65 6d 70 6c 61 74 65 } //100 hellcode_template
		$a_01_3 = {50 72 6f 78 79 42 79 70 61 73 73 } //100 ProxyBypass
		$a_01_4 = {53 63 61 6e 50 6f 72 74 52 61 6e 67 65 73 } //100 ScanPortRanges
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100) >=500
 
}