
rule HackTool_BAT_FrostyStash_AA_dha{
	meta:
		description = "HackTool:BAT/FrostyStash.AA!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 4d 52 5f 45 6e 67 69 6e 65 } //1 TMR_Engine
		$a_01_1 = {54 4d 52 5f 4b 65 65 70 41 6c 69 76 65 } //1 TMR_KeepAlive
		$a_01_2 = {54 4d 52 5f 50 69 6e 67 53 79 73 74 65 6d } //1 TMR_PingSystem
		$a_01_3 = {54 4d 52 5f 50 69 6e 67 4e 65 74 } //1 TMR_PingNet
		$a_01_4 = {54 4d 52 5f 43 68 65 63 6b 45 76 65 6e 74 } //1 TMR_CheckEvent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}