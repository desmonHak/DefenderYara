
rule Trojan_Win64_LokiBot_GVA_MTB{
	meta:
		description = "Trojan:Win64/LokiBot.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 20 63 6f 6d 6d 65 6e 74 20 62 65 6c 6f 77 20 63 6f 6e 74 61 69 6e 73 20 53 46 58 20 73 63 72 69 70 74 20 63 6f 6d 6d 61 6e 64 73 } //1 The comment below contains SFX script commands
		$a_01_1 = {53 65 74 75 70 3d 4f 72 64 69 6e 65 5f 30 31 2e 70 64 66 } //1 Setup=Ordine_01.pdf
		$a_01_2 = {53 65 74 75 70 3d 22 46 61 74 74 75 72 61 5f 42 65 72 6e 65 72 5f 31 34 38 33 34 37 30 34 31 34 5f 64 65 6c 20 33 30 2e 30 39 2e 32 30 32 35 2e 50 44 46 } //1 Setup="Fattura_Berner_1483470414_del 30.09.2025.PDF
		$a_02_3 = {53 65 74 75 70 3d [0-10] 2e 65 78 65 } //1
		$a_00_4 = {45 00 6e 00 74 00 65 00 72 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 66 00 6f 00 72 00 20 00 74 00 68 00 65 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 66 00 69 00 6c 00 65 00 3a 00 } //2 Enter password for the encrypted file:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*2) >=6
 
}