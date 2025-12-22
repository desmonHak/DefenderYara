
rule HackTool_BAT_FrostyStash_F_dha{
	meta:
		description = "HackTool:BAT/FrostyStash.F!dha,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c } //1 Kill
		$a_01_1 = {67 65 74 5f 4d 6f 64 75 6c 65 56 65 72 73 69 6f 6e 49 64 } //1 get_ModuleVersionId
		$a_01_2 = {67 65 74 5f 4d 65 73 73 61 67 65 } //1 get_Message
		$a_01_3 = {67 65 74 5f 55 73 65 72 4e 61 6d 65 } //1 get_UserName
		$a_01_4 = {67 65 74 5f 50 72 6f 63 65 73 73 4e 61 6d 65 } //1 get_ProcessName
		$a_01_5 = {67 65 74 5f 46 75 6c 6c 4e 61 6d 65 } //1 get_FullName
		$a_01_6 = {73 65 74 5f 43 6c 69 65 6e 74 53 69 7a 65 } //1 set_ClientSize
		$a_01_7 = {4a 61 76 61 53 63 72 69 70 74 53 65 72 69 61 6c 69 7a 65 72 } //1 JavaScriptSerializer
		$a_01_8 = {47 65 74 50 72 6f 63 65 73 73 65 73 } //1 GetProcesses
		$a_01_9 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_01_10 = {67 65 74 5f 50 6e 67 } //1 get_Png
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}