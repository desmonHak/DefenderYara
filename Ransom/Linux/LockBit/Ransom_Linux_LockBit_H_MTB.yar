
rule Ransom_Linux_LockBit_H_MTB{
	meta:
		description = "Ransom:Linux/LockBit.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 63 6b 42 69 74 20 35 2e 30 } //1 LockBit 5.0
		$a_01_1 = {2f 52 65 61 64 4d 65 46 6f 72 44 65 63 72 79 70 74 2e 74 78 74 } //1 /ReadMeForDecrypt.txt
		$a_01_2 = {2e 4c 4f 43 4b 45 52 } //1 .LOCKER
		$a_01_3 = {65 6e 63 72 79 70 74 5f 65 78 74 65 6e 73 69 6f 6e } //1 encrypt_extension
		$a_03_4 = {74 74 70 3a 2f 2f 6c 6f 63 6b 62 69 74 [0-50] 2e 6f 6e 69 6f 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}