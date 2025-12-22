
rule Ransom_Win64_LockFile_ARA_MTB{
	meta:
		description = "Ransom:Win64/LockFile.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //2 vssadmin delete shadows /all /quiet
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 } //1 encrypted
		$a_01_2 = {72 61 6e 73 6f 6d 77 61 72 65 } //1 ransomware
		$a_01_3 = {42 69 74 63 6f 69 6e } //1 Bitcoin
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}