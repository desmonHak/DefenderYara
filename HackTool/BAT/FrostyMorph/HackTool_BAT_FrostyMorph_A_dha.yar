
rule HackTool_BAT_FrostyMorph_A_dha{
	meta:
		description = "HackTool:BAT/FrostyMorph.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 72 70 68 65 72 } //1 Morpher
		$a_01_1 = {49 6e 6a 65 63 74 65 64 53 65 65 64 43 69 70 68 65 72 } //1 InjectedSeedCipher
		$a_01_2 = {44 65 63 72 79 70 74 53 74 72 69 6e 67 } //1 DecryptString
		$a_01_3 = {44 65 63 72 79 70 74 4c 6f 6e 67 } //1 DecryptLong
		$a_01_4 = {44 65 63 72 79 70 74 46 6c 6f 61 74 } //1 DecryptFloat
		$a_01_5 = {44 65 63 72 79 70 74 49 6e 74 } //1 DecryptInt
		$a_01_6 = {44 65 63 72 79 70 74 41 72 72 61 79 } //1 DecryptArray
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}