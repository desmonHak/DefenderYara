
rule Ransom_Win64_Neveda_YBH_MTB{
	meta:
		description = "Ransom:Win64/Neveda.YBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 69 6c 65 73 20 77 65 72 65 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 files were stolen and encrypted
		$a_01_1 = {50 61 79 20 61 20 72 61 6e 73 6f 6d 20 61 6e 64 20 73 61 76 65 20 79 6f 75 72 20 72 65 70 75 74 61 74 69 6f 6e } //1 Pay a ransom and save your reputation
		$a_01_2 = {70 6f 73 74 20 79 6f 75 72 20 63 72 69 74 69 63 61 6c 20 64 61 74 61 } //1 post your critical data
		$a_01_3 = {74 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 20 66 72 6f 6d 20 62 61 63 6b 75 70 73 } //1 to recover your files from backups
		$a_01_4 = {72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //1 rename encrypted files
		$a_01_5 = {74 68 65 79 20 63 6f 6e 74 61 69 6e 20 76 69 72 75 73 65 73 } //1 they contain viruses
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}