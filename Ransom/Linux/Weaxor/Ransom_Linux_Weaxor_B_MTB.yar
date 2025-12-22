
rule Ransom_Linux_Weaxor_B_MTB{
	meta:
		description = "Ransom:Linux/Weaxor.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 77 65 61 78 2e 70 68 70 } //1 /biweax.php
		$a_01_1 = {77 65 61 78 2e 74 78 74 } //1 weax.txt
		$a_01_2 = {64 65 63 79 72 70 74 69 6f 6e } //1 decyrption
		$a_01_3 = {52 45 43 4f 56 45 52 59 20 49 4e 46 4f 52 4d 41 54 49 4f 4e 2e 74 78 74 } //1 RECOVERY INFORMATION.txt
		$a_03_4 = {74 74 70 3a 2f 2f 77 65 61 78 6f 72 [0-55] 2e 6f 6e 69 6f 6e 2f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}