
rule HackTool_MacOS_MythicAgent_X3{
	meta:
		description = "HackTool:MacOS/MythicAgent.X3,SIGNATURE_TYPE_MACHOHSTR_EXT,fffffff4 01 fffffff4 01 05 00 00 "
		
	strings :
		$a_00_0 = {6a 73 6f 6e 3a 22 4b 69 6c 6c 64 61 74 65 22 } //100 json:"Killdate"
		$a_01_1 = {6b 65 79 73 74 72 6f 6b 65 73 } //100 keystrokes
		$a_01_2 = {63 32 5f 70 72 6f 66 69 6c 65 } //100 c2_profile
		$a_00_3 = {6a 73 6f 6e 3a 22 73 61 6e 64 62 6f 78 70 61 74 68 22 } //100 json:"sandboxpath"
		$a_00_4 = {6a 73 6f 6e 3a 22 77 65 62 68 6f 6f 6b } //100 json:"webhook
	condition:
		((#a_00_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*100+(#a_00_3  & 1)*100+(#a_00_4  & 1)*100) >=500
 
}