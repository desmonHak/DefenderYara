
rule VirTool_Win64_Comenesz_A{
	meta:
		description = "VirTool:Win64/Comenesz.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 67 65 6e 74 20 72 65 67 69 73 74 65 72 65 64 } //1 Agent registered
		$a_01_1 = {73 6c 65 65 70 46 6f 6c 69 61 67 65 } //1 sleepFoliage
		$a_01_2 = {74 61 6b 65 53 63 72 65 65 6e 73 68 6f 74 } //1 takeScreenshot
		$a_01_3 = {40 49 6d 70 65 72 73 6f 6e 61 74 65 64 } //1 @Impersonated
		$a_01_4 = {4a 69 74 74 65 72 } //1 Jitter
		$a_01_5 = {40 43 4d 44 5f 53 54 45 41 4c 5f 54 4f 4b 45 4e } //1 @CMD_STEAL_TOKEN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}