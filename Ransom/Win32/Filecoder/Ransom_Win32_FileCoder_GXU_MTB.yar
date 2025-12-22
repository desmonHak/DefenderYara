
rule Ransom_Win32_FileCoder_GXU_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.GXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 67 72 61 74 75 6c 61 74 69 6f 6e 73 2c 20 49 27 76 65 20 68 61 63 6b 65 64 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 } //1 Congratulations, I've hacked your computer
		$a_01_1 = {68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 75 73 69 6e 67 20 61 20 6d 69 6c 69 74 61 72 79 20 67 72 61 64 65 } //1 have been encrypted using a military grade
		$a_01_2 = {72 61 6e 73 6f 6d 40 } //1 ransom@
		$a_01_3 = {2e 6f 6e 69 6f 6e } //1 .onion
		$a_01_4 = {6e 6f 20 77 61 79 20 74 6f 20 72 65 63 6f 76 65 72 20 79 6f 75 72 20 66 69 6c 65 73 20 77 69 74 68 6f 75 74 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //1 no way to recover your files without the decryption key
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}