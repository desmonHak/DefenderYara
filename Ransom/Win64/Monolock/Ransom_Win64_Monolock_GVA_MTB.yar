
rule Ransom_Win64_Monolock_GVA_MTB{
	meta:
		description = "Ransom:Win64/Monolock.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 8b 49 18 48 89 f8 ff d1 83 f0 01 48 8b 54 24 30 48 8b 5c 24 78 4c 8b 44 24 38 4c 8b 4c 24 28 89 c1 48 8b 44 24 70 } //2
		$a_01_1 = {52 45 41 44 4d 45 5f 52 45 43 4f 56 45 52 2e 74 78 74 } //1 README_RECOVER.txt
		$a_01_2 = {59 4f 55 52 20 46 49 4c 45 53 20 48 41 56 45 20 42 45 45 4e 20 45 4e 43 52 59 50 54 45 } //1 YOUR FILES HAVE BEEN ENCRYPTE
		$a_01_3 = {2e 6f 6e 69 6f 6e } //1 .onion
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}