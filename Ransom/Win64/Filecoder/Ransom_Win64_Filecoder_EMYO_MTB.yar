
rule Ransom_Win64_Filecoder_EMYO_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.EMYO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {72 61 6e 73 6f 6d } //1 ransom
		$a_81_1 = {59 6f 75 72 45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 48 65 72 65 } //1 YourEncryptionKeyHere
		$a_81_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_81_3 = {64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 } //1 decrypt your files
		$a_81_4 = {72 61 6e 64 6f 6d 5f 64 65 76 69 63 65 } //1 random_device
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}