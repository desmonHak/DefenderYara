
rule Ransom_Win64_Bak_AN_MTB{
	meta:
		description = "Ransom:Win64/Bak.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 79 6f 75 72 20 69 6d 70 6f 72 74 61 6e 74 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 All your important files have been encrypted
		$a_01_1 = {52 65 63 6f 76 65 72 79 20 77 69 74 68 6f 75 74 20 6f 75 72 20 64 65 63 72 79 70 74 69 6f 6e 20 74 6f 6f 6c 20 69 73 20 69 6d 70 6f 73 73 69 62 6c 65 } //1 Recovery without our decryption tool is impossible
		$a_01_2 = {52 65 63 65 69 76 65 20 64 65 63 72 79 70 74 6f 72 20 61 6e 64 20 72 65 63 6f 76 65 72 20 61 6c 6c 20 66 69 6c 65 73 } //1 Receive decryptor and recover all files
		$a_01_3 = {68 65 6c 70 40 61 78 65 6c 67 6c 75 65 2e 73 74 6f 72 65 } //1 help@axelglue.store
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}