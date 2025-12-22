
rule Ransom_Win64_Devman_C{
	meta:
		description = "Ransom:Win64/Devman.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 61 74 68 20 74 6f 20 74 68 65 20 64 69 72 65 63 74 6f 72 79 20 74 6f 20 65 6e 63 72 79 70 74 20 28 63 61 6e 20 62 65 20 62 65 66 6f 72 65 20 6f 72 20 61 66 74 65 72 20 66 6c 61 67 73 29 } //1 Path to the directory to encrypt (can be before or after flags)
		$a_01_1 = {45 6e 63 72 79 70 74 69 6e 67 20 6f 6e 6c 79 20 70 72 6f 76 69 64 65 64 20 70 61 74 68 28 73 29 3a } //1 Encrypting only provided path(s):
		$a_01_2 = {45 72 72 6f 72 3a 20 66 61 69 6c 65 64 20 74 6f 20 69 6e 69 74 69 61 6c 69 7a 65 20 63 72 79 70 74 6f 20 62 61 63 6b 65 6e 64 } //1 Error: failed to initialize crypto backend
		$a_01_3 = {53 74 61 72 74 69 6e 67 20 6c 6f 63 61 6c 20 65 6e 63 72 79 70 74 69 6f 6e 2e 2e 2e } //1 Starting local encryption...
		$a_01_4 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 52 45 41 44 4d 45 3a } //1 Failed to create README:
		$a_01_5 = {64 61 74 61 5f 65 6e 63 72 79 70 74 6f 72 20 73 74 61 72 74 65 64 20 77 69 74 68 20 61 72 67 73 3a } //1 data_encryptor started with args:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}