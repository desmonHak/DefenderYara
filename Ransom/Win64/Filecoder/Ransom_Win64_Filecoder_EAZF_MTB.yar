
rule Ransom_Win64_Filecoder_EAZF_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.EAZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 Your files have been encrypted
		$a_81_1 = {64 65 63 72 79 70 74 20 74 68 65 6d } //1 decrypt them
		$a_81_2 = {63 6f 6e 66 69 67 2e 74 78 74 } //1 config.txt
		$a_81_3 = {6b 65 79 3d 79 6f 75 72 5f 73 65 63 72 65 74 5f 6b 65 79 } //1 key=your_secret_key
		$a_81_4 = {49 66 20 77 65 20 64 6f 6e 27 74 20 72 65 63 65 69 76 65 20 70 61 79 6d 65 6e 74 20 77 69 74 68 69 6e 20 37 20 64 61 79 73 2c 20 74 68 65 20 6b 65 79 20 77 69 6c 6c 20 62 65 20 64 65 6c 65 74 65 64 } //1 If we don't receive payment within 7 days, the key will be deleted
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}