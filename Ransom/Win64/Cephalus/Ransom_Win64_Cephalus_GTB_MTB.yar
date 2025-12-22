
rule Ransom_Win64_Cephalus_GTB_MTB{
	meta:
		description = "Ransom:Win64/Cephalus.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 6f 78 3a 39 31 43 32 34 } //2 Tox:91C24
		$a_01_1 = {77 65 20 68 61 76 65 20 73 74 6f 6c 65 6e 20 63 6f 6e 66 69 64 65 6e 74 69 61 6c 20 64 61 74 61 20 66 72 6f 6d 20 79 6f 75 72 20 69 6e 74 72 61 6e 65 74 } //2 we have stolen confidential data from your intranet
		$a_01_2 = {57 65 27 72 65 20 43 65 70 68 61 6c 75 73 2c } //2 We're Cephalus,
		$a_01_3 = {79 6f 75 72 20 69 6e 74 72 61 6e 65 74 20 68 61 73 20 62 65 65 6e 20 63 6f 6d 70 72 6f 6d 69 73 65 64 20 62 79 20 75 73 } //2 your intranet has been compromised by us
		$a_01_4 = {45 6d 62 72 61 63 65 20 69 74 20 61 6e 64 20 70 61 79 20 75 73 } //2 Embrace it and pay us
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}