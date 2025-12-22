
rule Trojan_BAT_Zusy_AN_MTB{
	meta:
		description = "Trojan:BAT/Zusy.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {01 13 1f 11 1f 16 12 18 28 ?? 00 00 0a 9c 11 1f 17 12 18 28 ?? 00 00 0a 9c 11 1f 18 12 18 28 } //1
		$a_81_1 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_4 = {45 78 65 72 63 69 63 69 6f 30 35 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Exercicio05.Properties.Resources
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}