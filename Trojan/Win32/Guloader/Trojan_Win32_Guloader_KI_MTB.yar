
rule Trojan_Win32_Guloader_KI_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {72 69 62 61 6c 64 6c 79 } //1 ribaldly
		$a_81_1 = {6d 6f 6e 74 72 65 6e 20 73 6c 65 73 76 69 67 65 72 } //1 montren slesviger
		$a_81_2 = {62 65 6c 6c 61 64 6f 6e 6e 61 20 6c 61 6e 64 62 72 75 67 73 6d 65 64 68 6a 6c 70 65 72 65 6e 20 73 6c 6f 70 65 64 } //1 belladonna landbrugsmedhjlperen sloped
		$a_81_3 = {68 6f 6c 74 65 } //1 holte
		$a_81_4 = {72 6f 61 6e 73 20 6e 65 64 72 69 76 6e 69 6e 67 65 72 6e 65 } //1 roans nedrivningerne
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}